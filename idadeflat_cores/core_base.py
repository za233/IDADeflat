class DeflatCore:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def process(self, entry : int, blocks : list[int]):
        print('[%s] start processing' % self.name)

    def get_result(self) -> dict[int, int]:
        return {}
