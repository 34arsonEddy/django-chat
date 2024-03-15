from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        user = get_user_model().objects.create_user(
            email = validated_data['email'],
            password = validated_data['password'],
            nom = validated_data.get('nom', ""),
            prenom = validated_data.get('prenom', "")
        )
        return user

    class Meta:
        model = get_user_model()
        fields = ["email", "password", "nom", "prenom"]
        extra_kwargs = {"password": {"write_only":True}}

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    id = serializers.CharField(max_length=15, read_only=True)
    password = serializers.CharField(max_length=255, write_only=True)

    def validate(self, data):
        email = data.get("email", None)
        password = data.get("password", None)

        if email is None:
            raise serializers.ValidationError("l'adresse email doit etre rempli!")

        if password is None:
            raise serializers.ValidationError("le mot de passe doit etre rempli!")
        
        user = authenticate(username=email, password=password)

        if user is None:
            raise serializers.ValidationError("l'email ou le mot de passe invalide")
        
        if not user.is_active:
            raise serializers.ValidationError("l'utilisateur est inactive")
        
        return {
            "email": user.email,
            "id": user.id
        }