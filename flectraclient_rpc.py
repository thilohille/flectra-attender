from xmlrpc.client import ServerProxy
import json

with open('config.json') as json_data_file:
    cfg = json.load(json_data_file)

class FlectraClient:

    def __init__(self, username, password):
        self.url = cfg["flectra"]["url"]
        self.db =  cfg["flectra"]["db"]
        self.username = username
        self.password = password
        self.uid = self.getUid()

    def getUid(self):
        common = ServerProxy('{}/xmlrpc/2/common'.format(self.url))
        common.version()
        return common.authenticate(self.db, self.username, self.password, {})

    def attendance_manual(self, attendance_id):
        models = ServerProxy('{}/xmlrpc/2/object'.format(self.url))
        return models.execute_kw(self.db, self.uid, self.password,
            'hr.employee', 'attendance_manual',
            [attendance_id,'hr_attendance.hr_attendance_action_my_attendances'], {})

    def attendance_check(self):
        models = ServerProxy('{}/xmlrpc/2/object'.format(self.url))
        return models.execute_kw(self.db, self.uid, self.password,
            'hr.employee', 'search_read',
            [[["user_id", "=", self.uid]], ["attendance_state", "name"]], {})

    def attendance_checkout(self):
        status = self.attendance_check()
        if status[0]["attendance_state"] != "checked_out":
            return self.attendance_manual(status[0]["id"])
        else: 
            return {'status': 1, 'text': 'already checked out'} 

    def attendance_checkin(self):
        status = self.attendance_check()
        if status[0]["attendance_state"] != "checked_in":
            return self.attendance_manual(status[0]["id"])
        else: 
            return {'status': 1, 'text': 'already checked in'} 

