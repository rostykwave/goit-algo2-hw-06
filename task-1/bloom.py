class BloomFilter:
    """
    Bloom Filter for efficient checking of element presence.

    Args:
        size: Size of a bit array (number of bits)
        num_hashes: Number of hash functions to be used
    """

    def __init__(self, size: int, num_hashes: int):
        if size <= 0:
            raise ValueError("Size of a filter must be greater than 0")
        if num_hashes <= 0:
            raise ValueError("Count of hash functions should be greater than 0")

        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [False] * size

    def _hash(self, item: str, seed: int) -> int:
        hash_value = hash(f"{item}{seed}")
        return abs(hash_value) % self.size

    def add(self, item: str) -> None:
        if item is None:
            return

        item_str = str(item)

        for i in range(self.num_hashes):
            index = self._hash(item_str, i)
            self.bit_array[index] = True

    def contains(self, item: str) -> bool:
        if item is None:
            return False

        item_str = str(item)

        for i in range(self.num_hashes):
            index = self._hash(item_str, i)
            if not self.bit_array[index]:
                return False

        return True


def check_password_uniqueness(bloom: BloomFilter,
                              new_passwords: list) -> dict:
    """Check the uniqueness of passwords using Bloom Filter."""
    if bloom is None:
        raise ValueError("BloomFilter can't be None")

    if new_passwords is None:
        return {}

    results = {}

    for password in new_passwords:
        if password is None:
            password_str = ""
        else:
            password_str = str(password)

        if bloom.contains(password_str):
            results[password_str] = "вже використаний"
        else:
            results[password_str] = "унікальний"

    return results


if __name__ == "__main__":

    bloom = BloomFilter(size=1000, num_hashes=3)

    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")
