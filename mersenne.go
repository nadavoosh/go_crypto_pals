package cryptopals

// import "fmt"

const (
	w         = 32
	n         = 624
	m         = 397
	r         = 31
	notSeeded = n + 1
	u         = 11
	d         = 0xFFFFFFFF
	s         = 7
	b         = 0x9D2C5680
	t         = 15
	c         = 0xEFC60000
	l         = 18

	upper_mask uint32 = 0x7FFFFFFF
	lower_mask uint32 = 0x80000000

	f              = 1812433253
	matrixA uint32 = 0x9908B0DF
)

type MT19937 struct {
	state []uint32
	index int
}

// New allocates a new instance of the 64bit Mersenne Twister.
// A seed can be set using the .Seed() or .SeedFromSlice() methods.
// If no seed is set explicitly, a default seed is used instead.
func NewMersenneTwister() *MT19937 {
	res := &MT19937{
		state: make([]uint32, n),
		index: notSeeded,
	}
	return res
}

// Initialize the generator from a seed
func (mt *MT19937) Seed(seed int) {
	x := mt.state
	x[0] = uint32(seed)
	for i := uint32(1); i < n; i++ {
		x[i] = f*(x[i-1]^(x[i-1]>>(w-2))) + i
	}
	mt.index = n
}

func (mt *MT19937) Uint32() uint32 {
	if mt.index >= n {
		if mt.index == notSeeded {
			mt.Seed(5489) // default seed ...
		}
		mt.twist()
	}
	y := mt.state[mt.index]
	y ^= (y >> u) & d
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= y >> l

	mt.index++
	return y
}

func (mt *MT19937) twist() {
	for i := 0; i < n; i++ {
		x := (mt.state[i] & upper_mask) + (mt.state[(i+1)%n] & lower_mask)
		xA := x >> 1
		if (x % 2) != 0 { // lowest bit of x is 1
			xA = xA ^ matrixA
		}
		mt.state[i] = mt.state[(i+m)%n] ^ xA
	}
	mt.index = 0
}

// func SeedFromUint32(y uint32) int {
// 	y ^= y << l
// 	y ^= (y << t) & c
// 	y ^= (y << s) & b
// 	y ^= (y << u) & d
// 	y := mt.state[mt.index]
// 	return y
// }
