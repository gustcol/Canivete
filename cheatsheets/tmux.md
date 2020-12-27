# tmux Cheatsheet

> Multiplexing the world.

## Shortcuts

Command                                     | Description
------------------------------------------- | -------------------------
<kbd>Ctrl+b</kbd> <kbd>"</kbd>              | split pane horizontally
<kbd>Ctrl+b</kbd> <kbd>%</kbd>              | split pane vertically
<kbd>Ctrl+b</kbd> <kbd>arrow key</kbd>      | switch pane
Hold <kbd>Ctrl+b</kbd> <kbd>arrow key</kbd> | resize pane
<kbd>Ctrl+b</kbd> <kbd>c</kbd>              | create a new window
<kbd>Ctrl+b</kbd> <kbd>n</kbd>              | move to the next window
<kbd>Ctrl+b</kbd> <kbd>p</kbd>              | move to the previous window
<kbd>Ctrl+b</kbd> <kbd>PgUp</kbd>           | scroll back
<kbd>Ctrl+b</kbd> <kbd>PgDown</kbd>         | scroll forward

## Mouse

### Disable Mouse Scrolling for Status Bar
```
unbind -n WheelUpStatus
unbind -n WheelDownStatus
```
