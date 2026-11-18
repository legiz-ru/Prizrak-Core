//go:build no_sudoku

package inbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

type SudokuOption struct {
	BaseOption
}

func (o SudokuOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Sudoku struct {
	*Base
}

func NewSudoku(*SudokuOption) (*Sudoku, error) {
	return nil, errors.New("Sudoku inbound is disabled by \"no_sudoku\" build tag")
}
