//go:build no_sudoku

package outbound

import "errors"

type Sudoku struct {
	*Base
}

type SudokuOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewSudoku(SudokuOption) (*Sudoku, error) {
	return nil, errors.New("Sudoku support is disabled by \"no_sudoku\" build tag")
}
