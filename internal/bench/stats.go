package bench

import (
	"sort"
	"time"
)

// outlierFactor is the multiple of the median above which a sample is counted
// as an outlier.  Outliers are a transport-agnostic proxy for re-dials.
const outlierFactor = 1.8

// Stats is the summarized latency of a single [Result].
type Stats struct {
	// Name mirrors [Result.Name].
	Name string

	// N is the number of successful samples summarized.
	N int

	// Errors and Redials mirror the corresponding [Result] fields.
	Errors  int
	Redials int

	// Outliers is the count of samples above outlierFactor times the median.
	Outliers int

	// Min, Avg, Median, P95 and Max summarize the latency distribution.
	Min    time.Duration
	Avg    time.Duration
	Median time.Duration
	P95    time.Duration
	Max    time.Duration

	// SetupErr is set when the target failed to build.
	SetupErr error
}

// Summarize computes [Stats] from r.
func (r Result) Summarize() (s Stats) {
	s = Stats{
		Name:     r.Name,
		N:        len(r.Durations),
		Errors:   r.Errors,
		Redials:  r.Redials,
		SetupErr: r.SetupErr,
	}

	if len(r.Durations) == 0 {
		return s
	}

	sorted := append([]time.Duration(nil), r.Durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}

	s.Min = sorted[0]
	s.Max = sorted[len(sorted)-1]
	s.Avg = sum / time.Duration(len(sorted))
	s.Median = sorted[len(sorted)/2]
	s.P95 = sorted[percentileIndex(len(sorted), 95)]

	threshold := time.Duration(float64(s.Median) * outlierFactor)
	for _, d := range sorted {
		if d > threshold {
			s.Outliers++
		}
	}

	return s
}

// percentileIndex returns the index into a sorted slice of length n for the
// given percentile p (0-100), clamped to the last element.
func percentileIndex(n, p int) (i int) {
	i = n * p / 100
	if i >= n {
		i = n - 1
	}

	return i
}
