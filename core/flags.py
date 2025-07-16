from enum import Enum

class StratFlags(Enum):
    oop: 1
    fun: 2

class LogFlags(Enum):
    debug: 1
    info: 2
    warn: 3
    error: 4
