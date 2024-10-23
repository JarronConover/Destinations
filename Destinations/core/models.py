from django.db import models
import hashlib

class User(models.Model):
    def hashPassword(self, password: str):
        hasher = hashlib.sha256()
        hasher.update(password.encode('UTF-8'))
        self.password_hash = hasher.hexdigest()

    def hashPassword(password: str):
        hasher = hashlib.sha256()
        hasher.update(password.encode('UTF-8'))
        password_hash = hasher.hexdigest()
        return password_hash

    id = models.BigAutoField(primary_key=True)
    name = models.TextField()
    email = models.TextField(unique=True)
    password_hash = models.TextField()

class Session(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.OneToOneField("User", on_delete=models.CASCADE)
    token = models.TextField(default='')

class Destination(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField()
    review = models.TextField()
    rating = models.IntegerField()
    user = models.ForeignKey("User", on_delete=models.CASCADE)
    share_publicly = models.BooleanField()
