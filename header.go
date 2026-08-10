package ip

import (
	"strconv"
	"strings"
)

func formatHeaderValues(values []string) string {
	total := 0

	for i, value := range values {
		if i > 0 {
			total += 2
		}

		total += len(value)
	}

	var b strings.Builder

	limit := min(total, maxErrorValueBytes)
	b.Grow(limit + 32)
	remaining := limit

	for i, value := range values {
		if i > 0 && remaining > 0 {
			separator := ", "

			if len(separator) > remaining {
				separator = separator[:remaining]
			}

			b.WriteString(separator)
			remaining -= len(separator)
		}

		if remaining == 0 {
			break
		}

		if len(value) > remaining {
			value = value[:remaining]
		}

		b.WriteString(value)
		remaining -= len(value)
	}

	if total > maxErrorValueBytes {
		b.WriteString("... (")
		b.WriteString(strconv.Itoa(total))
		b.WriteString(" bytes)")
	}

	return b.String()
}

func formatHeaderValue(value string) string {
	return formatHeaderValues([]string{value})
}

func (e *Extractor) selectHeaderValues(headers map[string][]string, selected [][]string, selectedKeys []string) (bool, error) {
	var (
		totalBytes      int
		totalValues     int
		found           bool
		ambiguousHeader string
	)

	for key, values := range headers {
		if len(values) == 0 {
			continue
		}

		idx, ok := e.indexForHeaderKey(key)
		if !ok {
			continue
		}

		found = true

		for _, value := range values {
			totalValues++
			if totalValues > e.maxHeaderValues {
				return false, &HeaderError{
					Header: e.headers[idx],
					Err:    &LimitError{Limit: e.maxHeaderValues, Actual: totalValues, Err: ErrTooManyHeaderValues},
				}
			}

			totalBytes += len(value)
			if totalBytes > e.maxHeaderBytes {
				return false, &HeaderError{
					Header: e.headers[idx],
					Err:    &LimitError{Limit: e.maxHeaderBytes, Actual: totalBytes, Err: ErrHeaderTooLarge},
				}
			}
		}

		chosenKey := selectedKeys[idx]
		if chosenKey == "" {
			selectedKeys[idx] = key
			selected[idx] = values

			continue
		}

		if e.strict {
			if ambiguousHeader == "" {
				ambiguousHeader = e.headers[idx]
			}

			continue
		}

		lower := e.headers[idx]
		chosenIsLower := chosenKey == lower
		keyIsLower := key == lower

		if (!chosenIsLower && keyIsLower) || (chosenIsLower == keyIsLower && key < chosenKey) {
			selectedKeys[idx] = key
			selected[idx] = values
		}
	}

	if ambiguousHeader != "" {
		return false, &HeaderError{Header: ambiguousHeader, Err: ErrAmbiguousHeader}
	}

	return found, nil
}

func (e *Extractor) indexForHeaderKey(key string) (int, bool) {
	if idx, ok := e.headerIndex[key]; ok {
		return idx, true
	}

	for _, idx := range e.headerIndexesByLength[len(key)] {
		if strings.EqualFold(key, e.headers[idx]) {
			return idx, true
		}
	}

	return 0, false
}
