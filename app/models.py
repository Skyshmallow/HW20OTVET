import json
from typing import Union

class DataController:
    def __init__(self) -> None:
        with open('app/data.json') as f:
            self._users = json.load(f)['users']

    def get_user_by_id(self, user_id: str) -> Union[dict, None]:
        for user in self._users:
            if user['id'] == user_id:
                return user
        return None

    def get_all_users(self) -> list:
        return self._users

    def get_all_users_names(self):
        return [u['name'] for u in self._users if u['role'] == 'user']
    
    def add_user(self, new_user: dict) -> None:
        self._users.append(new_user)
        self._save_to_file()

    def _save_to_file(self) -> None:
        with open('app/data.json', 'w') as f:
            json.dump({'users': self._users}, f, indent=2)

db = DataController()