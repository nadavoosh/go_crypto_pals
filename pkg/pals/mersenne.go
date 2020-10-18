package pals

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
	State []uint32
	Index int
}

// New allocates a new instance of the 64bit Mersenne Twister.
// A seed can be set using the .Seed() or .SeedFromSlice() methods.
// If no seed is set explicitly, a default seed is used instead.
func NewMersenneTwister() *MT19937 {
	res := &MT19937{
		State: make([]uint32, n),
		Index: notSeeded,
	}
	return res
}

// Initialize the generator from a seed
func (mt *MT19937) Seed(seed int) {
	x := mt.State
	x[0] = uint32(seed)
	for i := uint32(1); i < n; i++ {
		x[i] = f*(x[i-1]^(x[i-1]>>(w-2))) + i
	}
	mt.Index = n
}

func (mt *MT19937) Uint32() uint32 {
	if mt.Index >= n {
		if mt.Index == notSeeded {
			mt.Seed(5489) // default seed ...
		}
		mt.twist()
	}
	y := mt.State[mt.Index]
	y ^= (y >> u) & d
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= y >> l
	mt.Index++
	return y
}

func (mt *MT19937) twist() {
	for i := 0; i < n; i++ {
		x := (mt.State[i] & upper_mask) + (mt.State[(i+1)%n] & lower_mask)
		xA := x >> 1
		if (x % 2) != 0 { // lowest bit of x is 1
			xA = xA ^ matrixA
		}
		mt.State[i] = mt.State[(i+m)%n] ^ xA
	}
	mt.Index = 0
}

func Untemper(y_orig uint32) uint32 {
	y := untemperRight(y_orig, l, d)
	y = untemperLeft(y, t, c)
	y = untemperLeft(y, s, b)
	y = untemperRight(y, u, d)
	return y
}

func untemperRight(y, shift, mask uint32) uint32 {
	for i := w / int(shift); i >= 0; i-- {
		filter := uint32((1<<shift)-1) << uint32(i*int(shift))
		yt := (y >> shift & mask) & filter
		y = y ^ yt
	}
	return y
}

func untemperLeft(y, shift, mask uint32) uint32 {
	for i := 0; i <= w/int(shift); i++ {
		filter := uint32((1<<shift)-1) << uint32(i*int(shift))
		y = y ^ ((y << shift & mask) & filter)
	}
	return y
}
