package cache

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cznic/mathutil"
)

var (
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))
	footerStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	focusedStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle         = focusedStyle
	noStyle             = lipgloss.NewStyle()
	helpStyle           = blurredStyle
	cursorModeHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	focusedButton = focusedStyle.Render("[ Update ]")
	blurredButton = fmt.Sprintf("[ %s ]", blurredStyle.Render("Update"))
)

type Model struct {
	CachePath string
	Editor    Editor
	Table     table.Model

	// privates
	inputs      []textinput.Model
	focusIndex  int
	statusMsg   string
	statusTimer time.Duration
}

func NewModel(cachePath string, table *table.Model) Model {
	m := Model{
		CachePath:  cachePath,
		Editor:     NewEditor(),
		Table:      *table,
		inputs:     make([]textinput.Model, 4),
		focusIndex: 0,
	}
	for i := range len(m.inputs) {
		input := textinput.New()
		input.Cursor.Style = cursorStyle
		input.CharLimit = 256
		switch i {
		case 0:
			input.Placeholder = "host"
			input.Focus()
			input.PromptStyle = focusedStyle
			input.TextStyle = focusedStyle
		case 1:
			input.Placeholder = "ports"
			input.CharLimit = 5
		case 2:
			input.Placeholder = "protocol"
			input.CharLimit = 5

		case 3:
			input.Placeholder = "timestamp"
			input.CharLimit = 10
		}
		m.inputs[i] = input
	}

	return m
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// m.Table.SetWidth(msg.Width)
		// m.Table.SetHeight(msg.Height)
	case tea.KeyMsg:
		// do always regardless of state
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		}

		// do while editting table row
		if m.Editor.IsEditting() {
			switch msg.String() {
			case "esc":
				return m, m.editSelectedRow(false)
			case "w", "enter":
				return m, m.updateRow()
			// case "enter":
			// 	// Did the user press enter while the submit button was focused?
			// 	// If so, exit.
			// 	if m.focusIndex == len(m.inputs) {
			// 		return m, tea.Quit
			// 	}

			case "tab", "shift+tab", "up", "down":
				s := msg.String()
				switch s {
				case "up", "shift+tab":
					m.focusIndex = mathutil.Clamp(m.focusIndex-1, 0, len(m.inputs))
				case "down", "tab":
					m.focusIndex = mathutil.Clamp(m.focusIndex+1, 0, len(m.inputs))
				}

				cmds := make([]tea.Cmd, len(m.inputs))
				for i := range m.inputs {
					if i == m.focusIndex {
						// Set focused state
						cmds[i] = m.inputs[i].Focus()
						m.inputs[i].PromptStyle = focusedStyle
						m.inputs[i].TextStyle = focusedStyle
						continue
					}
					// Remove focused state
					m.inputs[i].Blur()
					m.inputs[i].PromptStyle = noStyle
					m.inputs[i].TextStyle = noStyle
				}
				return m, tea.Batch(cmds...)
			}
			cmd = m.updateInputs(msg)
			return m, tea.Batch(cmd)
			// do while making selection from table
		} else if m.Editor.IsSelecting() {
			switch msg.String() {
			case "enter":
				return m, m.editSelectedRow(true)
			case "esc":
				return m, tea.Quit
			case "ctrl+w":
				m.updateCacheData()
				return m, tea.Quit
			case "w", "ctrl+s":
				return m, m.updateCacheData()
			case "d":
				return m, m.deleteSelectedRow()
			case "a":
				return m, m.addRowAfterCursor()
			case "ctrl+a":
				return m, m.addRowAtEnd()
			case "q":
				return m, tea.Quit
			}
			m.Table, cmd = m.Table.Update(msg)
		}

	}
	return m, cmd
}

func (m Model) View() string {
	if m.Editor.IsEditting() {
		return m.editRowView()
	} else if m.Editor.IsSelecting() {
		display := m.Table.View() + "\n"
		display += footerStyle.Render(fmt.Sprintf(`
 j/k, ⬇/⬆ : move cursor;  enter: choose;  
 a: add row after cursor;  ctrl+a: add row at end
 d: delete row at cursor; 
 w, ctrl+s: save data;  
 ctrl+w: save and quit;  q, esc: quit w/o saving;
----------------------------------------------------------
 cache: %s
 cursor: %d, rows: %d
 %s
`, m.CachePath, m.Table.Cursor(), len(m.Table.Rows()), m.statusMsg))

		return baseStyle.Render(display + "\n")
	}
	return "Something went wrong..."
}

func (m *Model) displayMessage(message string, timeout time.Duration) {

	// show the message arg for alloted time
	m.statusMsg = message
	reset := make(chan string)
	go func() {
		time.Sleep(timeout)
		reset <- ""
	}()
	m.statusMsg = <-reset

}
