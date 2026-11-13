class AnalysisError(Exception):
    """A public error code without target content, private paths or credentials."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
