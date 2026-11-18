//go:build no_sudoku

package generator

import "errors"

func sudokuKeyPair() (privateKey string, publicKey string, err error) {
	return "", "", errors.New("Sudoku support is disabled by \"no_sudoku\" build tag")
}
