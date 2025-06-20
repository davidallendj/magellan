package cache

type editorState interface{}
type selecting struct{}
type editting struct{}

type Editor struct {
	state editorState
}

// transition between state

func NewEditor() Editor {
	return Editor{state: selecting{}}
}

func (e *Editor) StartEditting() editting {
	e.state = editting{}
	return e.state.(editting)
}

func (e *Editor) StopEditting() selecting {
	e.state = selecting{}
	return e.state.(selecting)
}

func (s editting) FinishEditting(e *Editor) selecting {
	e.state = selecting{}
	return e.state.(selecting)
}

func (e *Editor) GetState() editorState {
	return e.state
}

func (e *Editor) GetStateString() string {
	switch e.state.(type) {
	case selecting:
		return "selecting"
	case editting:
		return "editting"
	}
	return ""
}

func (e *Editor) IsEditting() bool {
	return e.GetStateString() == "editting"
}

func (e *Editor) IsSelecting() bool {
	return e.GetStateString() == "selecting"
}

func test() {
	editor := NewEditor()
	editting := editor.StartEditting()

	// ...later on...
	editting.FinishEditting(&editor)
}
