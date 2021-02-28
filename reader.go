// Copyright 2014 The zephyr-go authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zephyr

import (
	"bytes"
	"io"
	"log"
	"net"
	"time"

	"github.com/zephyr-im/krb5-go"
)

// MaxPacketLength is the maximum size of a zephyr notice on the wire.
const MaxPacketLength = 1024

// A RawReaderResult is an output of a ReadRawNotices call. It either
// contains a RawNotice and a source address or an error.
type RawReaderResult struct {
	RawNotice *RawNotice
	Addr      net.Addr
}

// ReadRawNotices decodes packets from a PacketConn into RawNotices
// and returns a stream of them. Non-fatal errors are returned through
// the stream. On a fatal error or EOF, the channel is closed.
func ReadRawNotices(conn net.PacketConn) <-chan RawReaderResult {
	sink := make(chan RawReaderResult)
	go readRawNoticeLoop(conn, sink)
	return sink
}

func readRawNoticeLoop(
	conn net.PacketConn,
	sink chan<- RawReaderResult,
) {
	defer close(sink)
	var buf [MaxPacketLength]byte
	var tempDelay time.Duration
	for {
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			// Send the error out to the consumer.
			if err != io.EOF {
				log.Printf("Error reading packet: %v\n", err)
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				// Delay logic from net/http.Serve.
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			break
		}
		tempDelay = 0

		// Copy the packet so we can reuse the buffer.
		raw, err := DecodePacket(copyByteSlice(buf[0:n]))
		if err != nil {
			log.Printf("Error decoding notice: %v\n", err)
			continue
		}
		sink <- RawReaderResult{raw, addr}
	}
}

// A NoticeReaderResult is an output of a ReadNoticesFromServer
// call. It either contains a notice with authentication status and
// source address or an error.
type NoticeReaderResult struct {
	Notice     *Notice
	AuthStatus AuthStatus
	Addr       net.Addr
}

// ReadNoticesFromServer decodes and authenticates notices sent from
// the server. Returns a channel containing authenticated notices and
// errors. The channel is closed on fatal errors. If keyCh is nil, all
// notices appear as AuthFailed. Additional keys can be added by sending
// on keyCh. Any keys in keyCh when this function is called are
// guaranteed to be read before the first message is authenticated.
func ReadNoticesFromServer(
	conn net.PacketConn,
	keyCh <-chan *krb5.KeyBlock,
) <-chan NoticeReaderResult {
	// TODO(davidben): Should this channel be buffered a little?
	sink := make(chan NoticeReaderResult)
	go readNoticeLoop(ReadRawNotices(conn), keyCh, sink)
	return sink
}

type keyCacheEntry struct {
	key      *krb5.KeyBlock
	sendTime time.Time
	firstUse time.Time
}

type keyCache struct {
	keys []*keyCacheEntry
}

func (kc *keyCache) add(key *krb5.KeyBlock, t time.Time) {
	for _, k := range kc.keys {
		if k.key.EncType == key.EncType && bytes.Equal(k.key.Contents, key.Contents) {
			k.sendTime = t
			k.firstUse = time.Time{}
			return
		}
	}
	kc.keys = append([]*keyCacheEntry{{
		key:      key,
		sendTime: t,
		firstUse: time.Time{},
	}}, kc.keys...)
}

const keyTimeout = 60 * time.Second

func (kc *keyCache) checkAuthFromServer(ctx *krb5.Context, rawNotice *RawNotice, t time.Time) AuthStatus {
	for _, k := range kc.keys {
		authStatus, err := rawNotice.CheckAuthFromServer(ctx, k.key)
		if err != nil {
			log.Printf("Error authenticating notice: %v", err)
			authStatus = AuthFailed
			// TODO: Are errors expected if the key doesn't match or should we return immediately?
		}
		if authStatus == AuthYes {
			if k.firstUse.IsZero() {
				k.firstUse = t
			} else {
				if t.Sub(k.firstUse) > keyTimeout {
					i := len(kc.keys) - 1
					for ; i >= 0; i-- {
						if k.sendTime.Sub(kc.keys[i].sendTime) < keyTimeout {
							break
						}
					}
					kc.keys = kc.keys[:i+1]
				}
			}
			return authStatus
		}
	}
	return AuthFailed
}

func readNoticeLoop(
	rawReader <-chan RawReaderResult,
	keyCh <-chan *krb5.KeyBlock,
	sink chan<- NoticeReaderResult,
) {
	defer close(sink)
	ctx, err := krb5.NewContext()
	if err != nil {
		log.Printf("Error creating krb5 context: %v", err)
		return
	}
	defer ctx.Free()
	var keys keyCache
	// Drain keyCh in case the caller wants us to start with keys.
Keys:
	for {
		select {
		case key := <-keyCh:
			keys.add(key, time.Now())
		default:
			break Keys
		}
	}
	// Now drain both rawReader and keyCh.
	for {
		select {
		case key := <-keyCh:
			keys.add(key, time.Now())
		case r, ok := <-rawReader:
			if !ok {
				return
			}
			notice, err := DecodeRawNotice(r.RawNotice)
			if err != nil {
				log.Printf("Error parsing notice: %v", err)
				continue
			}

			authStatus := AuthFailed
			if notice.Kind.IsACK() {
				// Don't bother; ACKs' auth bits are always lies.
				authStatus = AuthNo
			} else {
				authStatus = keys.checkAuthFromServer(ctx, r.RawNotice, time.Now())
			}
			sink <- NoticeReaderResult{notice, authStatus, r.Addr}
		}
	}
}
