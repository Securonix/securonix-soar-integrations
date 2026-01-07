from pykson import JsonObject, ObjectField

class RequestBody(JsonObject):

    parameters = ObjectField(dict)

    connectionParameters = ObjectField(dict)


