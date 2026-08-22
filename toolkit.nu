const current_dir = path self .

export def bootstrap [] {
    uv venv
    uv sync
}

