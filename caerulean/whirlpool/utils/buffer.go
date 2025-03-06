package utils

import (
	"crypto/rand"
	"fmt"
	"sync"
	"unsafe"
)

type Buffer struct {
	array           *[]byte
	start, end, cap uint
}

func NewBufferFromSlice(slice []byte) *Buffer {
	return &Buffer{
		array: &slice,
		start: 0,
		end:   uint(len(slice)),
		cap:   uint(cap(slice)),
	}
}

func NewClearBuffer(before, available, after uint) *Buffer {
	capacity := before + available + after
	array := make([]byte, capacity)
	return &Buffer{
		array: &array,
		start: before,
		end:   before + available,
		cap:   capacity,
	}
}

func NewEmptyBuffer(before, after uint) *Buffer {
	return NewClearBuffer(before, 0, after)
}

func NewRandomBuffer(size uint) (*Buffer, error) {
	slice := make([]byte, size)
	if _, err := rand.Read(slice[:size]); err != nil {
		return nil, fmt.Errorf("reading random buffer error: %v", err)
	}
	return &Buffer{
		array: &slice,
		start: 0,
		end:   uint(len(slice)),
		cap:   uint(cap(slice)),
	}, nil
}

func (b *Buffer) Length() uint {
	return b.end - b.start
}

func (b *Buffer) ForwardCap() uint {
	return b.cap - b.end
}

func (b *Buffer) BackwardCap() uint {
	return b.start
}

func (b *Buffer) BufferSize(slice []byte) (*Buffer, error) {
	selfSlice := (*b.array)[b.start:]
	if unsafe.Pointer(&slice[0]) == unsafe.Pointer(&selfSlice) {
		return &Buffer{
			array: b.array,
			start: b.start,
			end:   b.start + uint(len(slice)),
			cap:   b.cap,
		}, nil
	} else {
		return nil, fmt.Errorf("slices do not share the same starting point in memory!")
	}
}

func (b *Buffer) Get(pos uint) byte {
	return (*b.array)[b.start+pos]
}

func (b *Buffer) Set(pos uint, value byte) {
	(*b.array)[b.start+pos] = value
}

func (b *Buffer) Slice() []byte {
	return (*b.array)[b.start:b.end]
}

func (b *Buffer) ResliceStart(start uint) []byte {
	return (*b.array)[b.start+start : b.end]
}

func (b *Buffer) RebufferStart(start uint) *Buffer {
	return &Buffer{
		array: b.array,
		start: b.start + start,
		end:   b.end,
		cap:   b.cap,
	}
}

func (b *Buffer) ResliceEnd(end uint) []byte {
	return (*b.array)[b.start : b.start+end]
}

func (b *Buffer) RebufferEnd(end uint) *Buffer {
	return &Buffer{
		array: b.array,
		start: b.start,
		end:   b.start + end,
		cap:   b.cap,
	}
}

func (b *Buffer) Reslice(start, end uint) []byte {
	return (*b.array)[b.start+start : b.start+end]
}

func (b *Buffer) Rebuffer(start, end uint) *Buffer {
	return &Buffer{
		array: b.array,
		start: b.start + start,
		end:   b.start + end,
		cap:   b.cap,
	}
}

func (b *Buffer) AppendBuffer(buffer *Buffer) (*Buffer, error) {
	bufferLen := buffer.Length()
	if b.ForwardCap() >= bufferLen {
		newEnd := b.end + bufferLen
		copy((*b.array)[b.end:newEnd], buffer.Slice())
		return &Buffer{
			array: b.array,
			start: b.start,
			end:   newEnd,
			cap:   b.cap,
		}, nil
	} else {
		return nil, fmt.Errorf("insufficient forward capacity (%d) to accomodate buffer of size %d", b.ForwardCap(), bufferLen)
	}
}

func (b *Buffer) AppendBytes(buffer []byte) (*Buffer, error) {
	bufferLen := uint(len(buffer))
	if b.ForwardCap() >= bufferLen {
		newEnd := b.end + bufferLen
		copy((*b.array)[b.end:newEnd], buffer)
		return &Buffer{
			array: b.array,
			start: b.start,
			end:   newEnd,
			cap:   b.cap,
		}, nil
	} else {
		return nil, fmt.Errorf("insufficient forward capacity (%d) to accomodate slice of size %d", b.ForwardCap(), bufferLen)
	}
}

func (b *Buffer) PrependBuffer(buffer *Buffer) (*Buffer, error) {
	bufferLen := buffer.Length()
	if b.BackwardCap() >= bufferLen {
		newStart := b.start - bufferLen
		copy((*b.array)[newStart:b.start], buffer.Slice())
		return &Buffer{
			array: b.array,
			start: newStart,
			end:   b.end,
			cap:   b.cap,
		}, nil
	} else {
		return nil, fmt.Errorf("insufficient backward capacity (%d) to accomodate buffer of size %d", b.BackwardCap(), bufferLen)
	}
}

func (b *Buffer) PrependBytes(buffer []byte) (*Buffer, error) {
	bufferLen := uint(len(buffer))
	if b.BackwardCap() >= bufferLen {
		newStart := b.start - bufferLen
		copy((*b.array)[newStart:b.start], buffer)
		return &Buffer{
			array: b.array,
			start: newStart,
			end:   b.end,
			cap:   b.cap,
		}, nil
	} else {
		return nil, fmt.Errorf("insufficient backward capacity (%d) to accomodate buffer of size %d", b.BackwardCap(), bufferLen)
	}
}

func (b *Buffer) ExpandBefore(size uint) (*Buffer, error) {
	if b.BackwardCap() >= size {
		return &Buffer{
			array: b.array,
			start: b.start - size,
			end:   b.end,
			cap:   b.cap,
		}, nil
	} else {
		return nil, fmt.Errorf("insufficient backward capacity (%d) to expand by size %d", b.BackwardCap(), size)
	}
}

func (b *Buffer) ExpandAfter(size uint) (*Buffer, error) {
	if b.ForwardCap() >= size {
		return &Buffer{
			array: b.array,
			start: b.start,
			end:   b.end + size,
			cap:   b.cap,
		}, nil
	} else {
		return nil, fmt.Errorf("insufficient forward capacity (%d) to expand by size %d", b.ForwardCap(), size)
	}
}

type Pool struct {
	before, after uint
	pool          sync.Pool
}

func CreateBufferPool(before, after uint) *Pool {
	return &Pool{
		before: before,
		after:  after,
		pool: sync.Pool{
			New: func() any {
				buffer := make([]byte, before+after)
				return &buffer
			},
		},
	}
}

func (p *Pool) Get() *Buffer {
	array := p.pool.Get().(*[]byte)
	return NewBufferFromSlice(*array)
}

func (p *Pool) Put(buffer *Buffer) {
	p.pool.Put(buffer.array)
}
