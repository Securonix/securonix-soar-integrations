from pykson import JsonObject, StringField, IntegerField, ObjectField, BooleanField
import json

class ResponseBody(JsonObject):
    
    status = StringField()
    errorCode = StringField()
    httpCode = IntegerField()
    message = StringField()
    response = ObjectField(dict)
    input = ObjectField(dict)
    output = ObjectField(dict)
    incrementals = BooleanField()
    
    def to_dict(self):
        """Convert ResponseBody to a regular Python dict for JSON serialization."""
        return {
            "status": self.status,
            "errorCode": self.errorCode,
            "httpCode": self.httpCode,
            "message": self.message,
            "response": self.response,
            "input": self.input,
            "output": self.output,
            "incrementals": self.incrementals
        }
    
    def __str__(self):
        return json.dumps(self.to_dict())
    
    def __repr__(self):
        return self.__str__()

