# Keyper TUI (Terminal User Interface)

A beautiful, interactive Terminal User Interface for Keyper password manager.

## Features

- **Login/Register**: Secure authentication with master password
- **Secrets List**: Browse and search all your secrets
- **Secret Detail View**: View decrypted secret content with password masking
- **Create/Edit Secrets**: Interactive forms for managing secrets
- **Sync Status**: Real-time sync status and conflict indicators
- **Type Filtering**: Filter secrets by type (Credential, Text, Bank Card, Binary)
- **Search**: Quick search through your secrets

## Usage

Launch the TUI:

```bash
keyper tui
```

## Keyboard Shortcuts

### Global
- `Ctrl+C` - Quit the application
- `Esc` - Go back/cancel

### Login/Register Screen
- `Tab` / `Shift+Tab` - Navigate between fields
- `Enter` - Submit form or move to next field

### Secrets List
- `↑` / `↓` - Navigate through secrets
- `Enter` - View selected secret
- `n` - Create new secret
- `/` - Search mode
- `s` - Sync with server
- `r` - Reload secrets list
- `0` - Clear type filter
- `1` - Filter by Credentials
- `2` - Filter by Text/Notes
- `3` - Filter by Bank Cards
- `4` - Filter by Binary files
- `q` - Quit

### Secret Detail View
- `e` - Edit secret
- `d` - Delete secret
- `p` - Toggle password visibility
- `Esc` - Back to list

### Create/Edit Secret
- `Tab` / `Shift+Tab` - Navigate between fields
- `Ctrl+S` - Save secret
- `Esc` - Cancel and go back

## Screens

### 1. Login Screen
- Username input
- Master password input (masked)
- Login button
- Link to registration

### 2. Register Screen
- Username input
- Master password input (masked)
- Confirm password input (masked)
- Register button
- Link back to login

### 3. Secrets List
- Table view with columns: Name, Type, Status, Updated
- Sync status bar showing:
  - Last sync time
  - Pending changes count
  - Conflict count
- Search bar (activated with `/`)
- Type filter options

### 4. Secret Detail View
- Secret name and type
- Sync status badge
- Decrypted content display:
  - **Credentials**: Username, password (masked by default), URL, notes
  - **Text/Notes**: Content
  - **Bank Cards**: Card number (masked), cardholder, expiry, CVV (masked)
  - **Binary**: File information
- Password masking toggle with `p` key

### 5. Create/Edit Secret
- Name field
- Type-specific fields:
  - **Credentials**: Username, password, URL, notes
  - More types can be added in future
- Save/Cancel actions

## Styling

The TUI uses Lipgloss for styling with a modern, colorful theme:

- **Primary Color**: Purple (#7D56F4)
- **Success**: Green (#04B575)
- **Error**: Red (#EE6D66)
- **Warning**: Orange (#FFAA00)
- **Borders**: Rounded borders with subtle colors

## Security Features

- **Password Masking**: All sensitive fields are masked by default
- **Client-Side Encryption**: All encryption happens locally
- **Master Password**: Never sent to server
- **Session Management**: Automatic token refresh

## Implementation Details

### Architecture
- Built with [Bubbletea](https://github.com/charmbracelet/bubbletea) (Elm-inspired TUI framework)
- Styled with [Lipgloss](https://github.com/charmbracelet/lipgloss) (style definitions)
- Uses [Bubbles](https://github.com/charmbracelet/bubbles) components (text input, table, spinner)

### State Management
- Clean separation of screens
- Each screen is a self-contained Bubbletea model
- Navigation via message passing
- Proper error handling and loading states

### Files
- `model.go` - Main application model and screen routing
- `styles.go` - Lipgloss style definitions
- `login.go` - Login screen
- `register.go` - Registration screen
- `secrets_list.go` - Secrets list with table view
- `secret_detail.go` - Secret detail view with decryption
- `secret_create.go` - Secret creation form
- `secret_edit.go` - Secret editing form

## Future Enhancements

Potential improvements:
- Support for all secret types (not just credentials)
- Conflict resolution UI
- Bulk operations
- Export/import functionality
- Password generator
- Custom themes
- Vim keybindings option
