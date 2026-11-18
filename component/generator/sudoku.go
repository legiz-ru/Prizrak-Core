//go:build !no_sudoku

package generator

import "github.com/metacubex/mihomo/transport/sudoku"

func sudokuKeyPair() (privateKey string, publicKey string, err error) {
	return sudoku.GenKeyPair()
}
