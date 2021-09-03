const { v4 } = require("uuid");
const AWS = require("aws-sdk");
const dynamodb = new AWS.DynamoDB.DocumentClient()
    //const bcrypt = require('bcrypt');
const { KmsKeyringNode, buildClient, CommitmentPolicy } = require("@aws-crypto/client-node");
const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)


const generatorKeyId = "arn:aws:kms:ap-south-1:087637206114:key/67a288fd-84c9-463c-82d3-6c0f30b588f0";
const keyIds = ["arn:aws:kms:ap-south-1:087637206114:key/0861189b-9331-47db-b48c-94b39a38fda4"];

const keyring = new KmsKeyringNode({ generatorKeyId, keyIds })
const context = {
    stage: "userPassword",
    purpose: "userPassword",
    origin: "ap-south-1"
}


const encryptData = async(plaintext, context) => {

    console.log("password is : " + plaintext);
    try {
        const { result } = await encrypt(keyring, plaintext, { encryptionContext: context })
        console.log(result);
        return result;

    } catch (error) {
        console.log(error);

    }
};

const decryptData = async(encryptedData, context) => {
    try {
        const { plaintext, messageHeader } = await decrypt(keyring, encryptedData);
        Object.entries(context).forEach(([key, value]) => {

            if (messageHeader.encryptionContext[key] === value) {
                console.log("Awesome. It is matching!");

            }
            if (messageHeader.encryptionContext[key] !== value) {
                throw new Error("Someone has changed the data");
            }
        });

        console.log(" decrypt function " + plaintext);
        return plaintext.toString();

    } catch (error) {
        console.log(error);
    }

};




const userLogin = async(event) => {


    const { username } = JSON.parse(event.body);
    const { password } = JSON.parse(event.body);
    const { id } = JSON.parse(event.body);

    if (!username) {
        return {
            statusCode: 400,
            body: JSON.stringify({
                message: 'Username  is required'
            }),
        };
    }
    if (!password) {
        return {
            statusCode: 400,
            body: JSON.stringify({
                message: 'Password  is required'
            }),
        };
    }


    let userResult;

    try {
        const result = await dynamodb.get({
            TableName: "UserTable",
            Key: { username }
        }).promise();

        userResult = result.Item;

        if (!userResult) {
            return {
                statusCode: 403,
                body: JSON.stringify({
                    message: 'User does not exist '
                }),
            };
        } else {


            const decryptPassword = await decryptData(userResult.password, context);
            console.log("Decrypt Password : " + decryptPassword);
            if (decryptPassword === password) {
                return {
                    statusCode: 200,
                    body: JSON.stringify({
                        message: 'User Login True ',
                        loginStatus: true
                    }),
                };
            } else {
                return {
                    statusCode: 403,
                    body: JSON.stringify({
                        message: 'Username Or Password Invalid ',
                        loginStatus: false
                    }),
                };
            }



        }







    } catch (error) {
        console.log(error);
    }



};
const fetchAllUsers = async(event) => {

    let allUsers;

    try {

        const results = await dynamodb.scan({ TableName: "UserTable" }).promise();
        allUsers = results.Items;

        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Fetch All Users successfully!',
                input: allUsers,
            }),
        };

    } catch (error) {

        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'User Registration Error',
                body: error,
            }),
        };

    }


    // Use this code if you don't use the http event with the LAMBDA-PROXY integration
    // return { message: 'Go Serverless v1.0! Your function executed successfully!', event };
};
const userReg = async(event) => {

    const { fname } = JSON.parse(event.body);
    const { lname } = JSON.parse(event.body);
    const { email } = JSON.parse(event.body);
    const { phone } = JSON.parse(event.body);
    const { username } = JSON.parse(event.body);
    const { password } = JSON.parse(event.body);
    const createAt = new Date().toISOString();
    const id = v4();


    // Validation
    if (!username) {
        return {
            statusCode: 400,
            body: JSON.stringify({
                message: 'Username  is required'
            }),
        };
    }
    if (!password) {
        return {
            statusCode: 400,
            body: JSON.stringify({
                message: 'Password  is required'
            }),
        };
    }

    //password encrypt 
    const Password = await encryptData(password, context);

    const newUser = {
        id,
        fname,
        lname,
        email,
        phone,
        username,
        Password,
        createAt
    }
    try {

        await dynamodb.put({
            TableName: "UserTable",
            Item: newUser
        }).promise()


        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'New User Added successfully!',
                body: newUser,
            }),
        };

    } catch (error) {
        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'User Registration Error',
                body: error,
            }),
        };

    }



    // Use this code if you don't use the http event with the LAMBDA-PROXY integration
    // return { message: 'Go Serverless v1.0! Your function executed successfully!', event };
};

module.exports = {
    userReg,
    userLogin,
    fetchAllUsers
};