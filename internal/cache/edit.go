package cache

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/araddon/dateparse"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/cznic/mathutil"
	"github.com/davidallendj/magellan/internal/cache/sqlite"
	magellan "github.com/davidallendj/magellan/pkg"
	"github.com/rs/zerolog/log"
)

func (m *Model) editSelectedRow(value bool) tea.Cmd {
	if value {
		row := m.Table.SelectedRow()
		for i := range m.inputs {
			m.inputs[i].SetValue(row[i])
		}
		m.Editor.StartEditting()
	} else {
		m.Editor.StopEditting()
	}
	return nil
}

func (m *Model) updateRow() tea.Cmd {
	// get updated values from inputs
	updated := make(table.Row, len(m.inputs))
	for i, input := range m.inputs {
		updated[i] = input.Value()
	}

	// update table for selected row
	rows := m.Table.Rows()
	rows[m.Table.Cursor()] = updated
	m.Table.SetRows(rows)

	// go back to selecting view
	m.Editor.StopEditting()
	m.displayMessage(fmt.Sprintf("updated row at index %d", m.Table.Cursor()), 3)
	return nil
}

func (m *Model) addRowAfterCursor() tea.Cmd {
	position := mathutil.Clamp(m.Table.Cursor()+1, 0, len(m.Table.Rows())-1)
	rows := slices.Insert(m.Table.Rows(), position, table.Row{
		"https://127.0.0.1",
		"443",
		"tcp",
		fmt.Sprintf("%d", time.Now().Unix()),
	})

	m.Table.SetRows(rows)
	m.displayMessage(fmt.Sprintf("add new row at index %d", m.Table.Cursor()+1), 3)
	return nil
}

func (m *Model) addRowAtEnd() tea.Cmd {
	rows := append(m.Table.Rows(), table.Row{
		"https://127.0.0.1",
		"443",
		"tcp",
		fmt.Sprintf("%d", time.Now().Unix()),
	})
	m.Table.SetRows(rows)
	m.displayMessage(fmt.Sprintf("add new row at index %d", len(m.Table.Rows())), 3)
	return nil
}

func (m *Model) deleteSelectedRow() tea.Cmd {
	if len(m.Table.Rows()) == 0 {
		m.displayMessage("nothing to delete...", 3)
		return nil
	}
	m.Table.SetRows(slices.Delete(m.Table.Rows(), m.Table.Cursor(), m.Table.Cursor()+1))
	m.displayMessage(fmt.Sprintf("deleted row at index %d", m.Table.Cursor()), 3)
	return nil
}

func (m *Model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))

	// Only text inputs with Focus() set will respond, so it's safe to simply
	// update all of them here without any further logic.
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m *Model) editRowView() string {
	display := fmt.Sprintf("Editting row %d...\n\n", m.Table.Cursor())

	// update the values of each input
	const lc = 9
	for i := range m.inputs {
		diff := lc - len(m.Table.Columns()[i].Title)
		spacing := strings.Repeat(" ", diff)
		// m.inputs[i].SetValue(row[i])
		display += fmt.Sprintf("%d: ", i)
		display += m.Table.Columns()[i].Title + ": "
		display += spacing + m.inputs[i].View() + "\n"
	}

	// submit button
	// button := &blurredButton
	// if m.focusIndex == len(m.inputs) {
	// 	button = &focusedButton
	// }
	// display += fmt.Sprintf("\n\n%s\n\n", *button)

	// add helper info in footer
	display += footerStyle.Render(`
 ⬇/⬆: move cursor; 
 w, enter: save edit;  esc: cancel;  ctrl+c: quit w/o saving;
`)

	return display
}

func (m *Model) updateCacheData() tea.Cmd {
	// create assets from table data
	assets := []magellan.RemoteAsset{}
	for _, row := range m.Table.Rows() {
		// convert port
		port, err := strconv.ParseInt(row[1], 10, 32)
		if err != nil {
			log.Error().Err(err).Str("host", row[0]).Msg("failed to parse port value")
			return nil
		}

		// parse timestamp
		timestamp, err := dateparse.ParseAny(row[3])
		if err != nil {
			log.Error().Err(err).Str("host", row[0]).Msg("failed to parse date/time")
			return nil
		}

		assets = append(assets, magellan.RemoteAsset{
			Host:      row[0],
			Port:      int(port),
			Protocol:  row[2],
			Timestamp: timestamp,
		})
	}

	// remove current database file
	err := os.Remove(m.CachePath)
	if err != nil {
		log.Error().Err(err).Str("path", m.CachePath).Msg("failed to remove old cache")
		return nil
	}

	// create the file again...
	_, err = sqlite.CreateRemoteAssetsIfNotExists(m.CachePath)
	if err != nil {
		log.Error().Err(err).Str("path", m.CachePath).Msg("failed to create new cache")
		return nil
	}

	// write assets to database
	err = sqlite.InsertRemoteAssets(m.CachePath, assets...)
	if err != nil {
		log.Error().Err(err).Str("path", m.CachePath).Msg("failed to insert data into cache")
		return nil
	}
	return nil
}
