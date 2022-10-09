set encoding=utf-8

set nocompatible

set expandtab
set tabstop=4
set softtabstop=4
set shiftwidth=4
set backspace=2
set nobackup
set noswapfile
set ruler
set nowritebackup
set showcmd
set laststatus=2 " Always display the status line
set number
set splitright
set showmatch
set noerrorbells visualbell t_vb=


" Searching
set incsearch
set hlsearch
set ignorecase
set smartcase


if (&t_Co > 2 || has("gui_running")) && !exists("syntax_on")
    syntax on
endif

set mouse=a
if exists('$TMUX')  " Support resizing in tmux
  set ttymouse=xterm2
endif
