from pykson import JsonObject, StringField, IntegerField, ObjectField, BooleanField

class ResponseBody(JsonObject):
    
    status = StringField()
    errorCode = StringField()
    httpCode = IntegerField()
    message = StringField()
    response = ObjectField(dict)
    input = ObjectField(dict)
    output = ObjectField(dict)
    incrementals = BooleanField()

