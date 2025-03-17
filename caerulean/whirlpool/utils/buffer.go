package utils

import (
	"crypto/rand"
	"fmt"
	"sync"
	"unsafe"
)

type Buffer struct {
	array           *[]byte
	start, end, cap int
}

func NewBufferFromSlice(slice []byte) *Buffer {
	return &Buffer{
		array: &slice,
		start: 0,
		end:   len(slice),
		cap:   cap(slice),
	}
}

func NewBufferFromSliceWithCapacity(slice []byte, before, after int) *Buffer {
	buffer := NewClearBuffer(before, len(slice), after)
	copy(buffer.Slice(), slice)
	return buffer
}

func NewClearBuffer(before, available, after int) *Buffer {
	capacity := before + available + after
	array := make([]byte, capacity)
	return &Buffer{
		array: &array,
		start: before,
		end:   before + available,
		cap:   capacity,
	}
}

func NewEmptyBuffer(before, after int) *Buffer {
	return NewClearBuffer(before, 0, after)
}

func NewRandomBuffer(size int) (*Buffer, error) {
	slice := make([]byte, size)
	if _, err := rand.Read(slice[:size]); err != nil {
		return nil, fmt.Errorf("reading random buffer error: %v", err)
	}
	return &Buffer{
		array: &slice,
		start: 0,
		end:   len(slice),
		cap:   cap(slice),
	}, nil
}

func (b *Buffer) newBufferFrom(start, end int) *Buffer {
	if start < 0 {
		panic(fmt.Sprintf("Buffer start position can't be negative (%d)!", start))
	} else if start > end {
		panic(fmt.Sprintf("Buffer start position can't be greater than buffer end position (%d > %d)!", start, end))
	} else if start > b.cap {
		panic(fmt.Sprintf("Buffer start position can't be greater than buffer capacity (%d > %d)!", start, b.cap))
	}
	if end < 0 {
		panic(fmt.Sprintf("Buffer end position can't be negative (%d)!", end))
	} else if end > b.cap {
		panic(fmt.Sprintf("Buffer end position can't be greater than buffer capacity (%d > %d)!", end, b.cap))
	}
	return &Buffer{
		array: b.array,
		start: start,
		end:   end,
		cap:   b.cap,
	}
}

func (b *Buffer) Length() int {
	return b.end - b.start
}

func (b *Buffer) ForwardCap() int {
	return b.cap - b.end
}

func (b *Buffer) BackwardCap() int {
	return b.start
}

func (b *Buffer) EnsureSameBuffers(slice []byte) (*Buffer, error) {
	selfSlice := (*b.array)[b.start:]
	if unsafe.Pointer(&slice[0]) == unsafe.Pointer(&selfSlice[0]) {
		return b.newBufferFrom(b.start, b.start+len(slice)), nil
	} else {
		return nil, fmt.Errorf("slices do not share the same starting point in memory")
	}
}

func (b *Buffer) Get(pos int) byte {
	getPos := b.start + pos
	if getPos < b.start {
		panic(fmt.Sprintf("Can't get beyond buffer start (%d < %d)!", getPos, b.start))
	} else if getPos >= b.end {
		panic(fmt.Sprintf("Can't get beyond buffer end (%d >= %d)!", getPos, b.end))
	}
	return (*b.array)[getPos]
}

func (b *Buffer) Set(pos int, value byte) {
	setPos := b.start + pos
	if setPos < b.start {
		panic(fmt.Sprintf("Can't set beyond buffer start (%d < %d)!", setPos, b.start))
	} else if setPos >= b.end {
		panic(fmt.Sprintf("Can't set beyond buffer end (%d >= %d)!", setPos, b.end))
	}
	(*b.array)[b.start+pos] = value
}

func (b *Buffer) Slice() []byte {
	return (*b.array)[b.start:b.end]
}

func (b *Buffer) ResliceStart(start int) []byte {
	return b.Reslice(start, b.end-b.start)
}

func (b *Buffer) RebufferStart(start int) *Buffer {
	return b.Rebuffer(start, b.end-b.start)
}

func (b *Buffer) ResliceEnd(end int) []byte {
	return b.Reslice(0, end)
}

func (b *Buffer) RebufferEnd(end int) *Buffer {
	return b.Rebuffer(0, end)
}

func (b *Buffer) Reslice(start, end int) []byte {
	startPos := b.start + start
	if startPos < b.start {
		panic(fmt.Sprintf("Can't have slice start beyond buffer start (%d < %d)!", startPos, b.start))
	} else if startPos >= b.end {
		panic(fmt.Sprintf("Can't have slice start beyond buffer end (%d >= %d)!", startPos, b.end))
	}
	endPos := b.start + end
	if endPos < b.start {
		panic(fmt.Sprintf("Can't have slice end beyond buffer start (%d < %d)!", endPos, b.start))
	} else if endPos > b.end {
		panic(fmt.Sprintf("Can't have slice end beyond buffer end (%d >= %d)!", endPos, b.end))
	}
	return (*b.array)[startPos:endPos]
}

func (b *Buffer) Rebuffer(start, end int) *Buffer {
	startPos := b.start + start
	if startPos < b.start {
		panic(fmt.Sprintf("Can't have new buffer start beyond old buffer start (%d < %d)!", startPos, b.start))
	} else if startPos >= b.end {
		panic(fmt.Sprintf("Can't have new buffer start beyond old buffer end (%d >= %d)!", startPos, b.end))
	}
	endPos := b.start + end
	if endPos < b.start {
		panic(fmt.Sprintf("Can't have new buffer end beyond old buffer start (%d < %d)!", endPos, b.start))
	} else if endPos > b.end {
		panic(fmt.Sprintf("Can't have new buffer end beyond old buffer end (%d >= %d)!", endPos, b.end))
	}
	return b.newBufferFrom(startPos, endPos)
}

func (b *Buffer) AppendBytes(buffer []byte) (*Buffer, error) {
	bufferLen := len(buffer)
	if b.ForwardCap() >= bufferLen {
		newEnd := b.end + bufferLen
		copy((*b.array)[b.end:newEnd], buffer)
		return b.newBufferFrom(b.start, newEnd), nil
	} else {
		return nil, fmt.Errorf("insufficient forward capacity (%d) to accommodate slice of size %d", b.ForwardCap(), bufferLen)
	}
}

func (b *Buffer) AppendBuffer(buffer *Buffer) (*Buffer, error) {
	return b.AppendBytes(buffer.Slice())
}

func (b *Buffer) PrependBytes(buffer []byte) (*Buffer, error) {
	bufferLen := len(buffer)
	if b.BackwardCap() >= bufferLen {
		newStart := b.start - bufferLen
		copy((*b.array)[newStart:b.start], buffer)
		return b.newBufferFrom(b.start-bufferLen, b.end), nil
	} else {
		return nil, fmt.Errorf("insufficient backward capacity (%d) to accommodate buffer of size %d", b.BackwardCap(), bufferLen)
	}
}

func (b *Buffer) PrependBuffer(buffer *Buffer) (*Buffer, error) {
	return b.PrependBytes(buffer.Slice())
}

func (b *Buffer) ExpandBefore(size int) (*Buffer, error) {
	return b.Expand(size, 0)
}

func (b *Buffer) ExpandAfter(size int) (*Buffer, error) {
	return b.Expand(0, size)
}

func (b *Buffer) Expand(before, after int) (*Buffer, error) {
	if before < 0 {
		panic(fmt.Sprintf("Can't expand backward by a negative value (%d)!", before))
	} else if b.BackwardCap() < before {
		return nil, fmt.Errorf("insufficient backward capacity (%d) to expand by size %d", b.BackwardCap(), before)
	}
	if after < 0 {
		panic(fmt.Sprintf("Can't expand forward by a negative value (%d)!", after))
	} else if b.ForwardCap() < after {
		return nil, fmt.Errorf("insufficient forward capacity (%d) to expand by size %d", b.ForwardCap(), after)
	}
	return b.newBufferFrom(b.start-before, b.end+after), nil
}

type Pool struct {
	before, after int
	pool          sync.Pool
}

func CreateBufferPool(before, after int) *Pool {
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

func (p *Pool) Get(length int) *Buffer {
	array := p.pool.Get().(*[]byte)
	buffer := NewBufferFromSlice(*array)
	return buffer.Rebuffer(p.before, p.before+length)
}

func (p *Pool) GetFull() *Buffer {
	return p.Get(p.after)
}

func (p *Pool) Put(buffer *Buffer) {
	p.pool.Put(buffer.array)
}
