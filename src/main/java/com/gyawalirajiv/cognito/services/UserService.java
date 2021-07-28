package com.gyawalirajiv.cognito.services;

import com.gyawalirajiv.cognito.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Value("${clientId}")
    private String clientId;
    @Value("${secretId}")
    private String secretId;

    public User signup(User user) throws NoSuchAlgorithmException, InvalidKeyException {
        CognitoIdentityProviderClient identityProviderClient = CognitoIdentityProviderClient.builder()
                .region(Region.AP_SOUTH_1)
                .build();

        signup(identityProviderClient,
                clientId,
                secretId,
                user.getUserName(),
                user.getPassword(),
                user.getEmail());
        identityProviderClient.close();
        return new User(user.getUserName(), null, user.getEmail());
    }

    private void signup(CognitoIdentityProviderClient identityProviderClient, String clientId, String secretKey, String userName, String password, String email) throws InvalidKeyException, NoSuchAlgorithmException {
        AttributeType attributeType = AttributeType.builder()
                .name("email")
                .value(email)
                .build();
        List<AttributeType> attrs = new ArrayList<>();
        attrs.add(attributeType);

        String secretVal = calculateSecretHash(clientId, secretKey, userName);
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .userAttributes(attrs)
                .username(userName)
                .clientId(clientId)
                .password(password)
                .secretHash(secretVal)
                .build();
        identityProviderClient.signUp(signUpRequest);
        System.out.println("User has been signed up.");
    }

    private String calculateSecretHash(String clientId, String secretKey, String userName) throws NoSuchAlgorithmException, InvalidKeyException {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
        SecretKeySpec singingKey = new SecretKeySpec(
                secretKey.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
        mac.init(singingKey);
        mac.update(userName.getBytes(StandardCharsets.UTF_8));
        byte[] rawHmac = mac.doFinal(clientId.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(rawHmac);
    }

    public List<User> getAll() {
        CognitoIdentityProviderClient identityProviderClient = CognitoIdentityProviderClient.builder()
                .region(Region.AP_SOUTH_1)
                .build();
        try {
            ListUsersRequest usersRequest = ListUsersRequest.builder()
                    .userPoolId("ap-south-1_qJh7jviPB")
                    .build();
            ListUsersResponse response = identityProviderClient.listUsers(usersRequest);

            List<User> users = response.users().stream().map(userType -> new User(userType.username(), null, null)).collect(Collectors.toList());
            return users;
        } catch (CognitoIdentityProviderException e){
            throw new RuntimeException("Something went Wrong!");
        }
    }
}
