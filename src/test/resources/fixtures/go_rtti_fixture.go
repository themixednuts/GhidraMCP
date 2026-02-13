package main

import (
	"os"
	"reflect"
)

type Worker interface {
	Work() int
}

type WorkerImpl struct {
	Value int
}

func (w *WorkerImpl) Work() int {
	return w.Value + 7
}

func consumeInterface(w Worker) int {
	return w.Work()
}

func main() {
	impl := &WorkerImpl{Value: 35}
	var worker Worker = impl

	result := consumeInterface(worker)
	result += int(reflect.TypeOf(worker).String()[0])
	result += int(reflect.TypeOf(*impl).String()[0])
	os.Exit(result & 0xff)
}
