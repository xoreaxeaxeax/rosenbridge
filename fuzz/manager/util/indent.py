import sys
import inspect

class AutoIndent(object):
    def __init__(self, stream, depth=len(inspect.stack())):
        self.stream = stream
        self.depth = depth

    def indent_level(self):
        return len(inspect.stack()) - self.depth

    def write(self, data):
        indentation = '  ' * self.indent_level()
        def indent(l):
            if l:
                return indentation + l
            else:
                return l
        data = '\n'.join([indent(line) for line in data.split('\n')])
        self.stream.write(data)

def initialize_indent():
    sys.stdout = AutoIndent(sys.stdout)

