package utils

import (
	"fmt"
	"sort"
	"time"
)

// medianTimeBlocks is the number of previous blocks which should be
// used to calculate the median time used to validate block timestamps.
const medianTimeBlocks = 11

// CalcPastMedianTime calculates the median time of the previous few blocks
// prior to, and including, the block node.
//
// This function is safe for concurrent access.
func CalcPastMedianTime(timestamps []int) (time.Time, error) {
	if len(timestamps) > medianTimeBlocks {
		return time.Time{}, fmt.Errorf("too many timestamps for median "+
			"time calculation - got %v, max %v", len(timestamps),
			medianTimeBlocks)
	}

	numNodes := len(timestamps)

	// Sort the timestamps.
	sort.Ints(timestamps)

	// NOTE: The consensus rules incorrectly calculate the median for even
	// numbers of blocks.  A true median averages the middle two elements
	// for a set with an even number of elements in it.   Since the constant
	// for the previous number of blocks to be used is odd, this is only an
	// issue for a few blocks near the beginning of the chain.  I suspect
	// this is an optimization even though the result is slightly wrong for
	// a few of the first blocks since after the first few blocks, there
	// will always be an odd number of blocks in the set per the constant.
	//
	// This code follows suit to ensure the same rules are used, however, be
	// aware that should the medianTimeBlocks constant ever be changed to an
	// even number, this code will be wrong.
	medianTimestamp := int64(timestamps[numNodes/2])
	return time.Unix(medianTimestamp, 0), nil
}
