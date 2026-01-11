package bloom

import "errors"

var (
	// ErrIncompatibleFilters is returned when trying to merge filters with different parameters
	ErrIncompatibleFilters = errors.New("bloom filters have incompatible parameters (m or k differ)")
)
