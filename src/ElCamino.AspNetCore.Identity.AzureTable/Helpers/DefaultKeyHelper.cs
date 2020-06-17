﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ElCamino.AspNetCore.Identity.AzureTable.Model;

namespace ElCamino.AspNetCore.Identity.AzureTable.Helpers
{
    public class DefaultKeyHelper : IKeyHelper
    {
        public string GeneratePartitionKeyIndexByLogin(string plainLoginProvider, string plainProviderKey)
        {
            string strTemp = $"{plainLoginProvider?.ToUpper()}_{plainProviderKey?.ToUpper()}";
            string hash = ConvertKeyToHash(strTemp);
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserLogin, hash);
        }

        public string GenerateRowKeyUserEmail(string plainEmail)
        {
            string hash = ConvertKeyToHash(plainEmail?.ToUpper());
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserEmail, hash);
        }

        public string GenerateUserId()
        {
            return Guid.NewGuid().ToString("N");
        }

        public string GenerateRowKeyUserId(string plainUserId)
        {
            string hash = ConvertKeyToHash(plainUserId?.ToUpper());
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserId, hash);
        }

        public string GenerateRowKeyUserName(string plainUserName)
        {
            return GeneratePartitionKeyUserName(plainUserName);
        }

        public string GeneratePartitionKeyUserName(string plainUserName)
        {
            string hash = ConvertKeyToHash(plainUserName?.ToUpper());
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserName, hash);
        }

        public string GenerateRowKeyIdentityUserRole(string plainRoleName)
        {
            string hash = ConvertKeyToHash(plainRoleName?.ToUpper());
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserRole, hash);
        }

        public string GenerateRowKeyIdentityRole(string plainRoleName)
        {
            string hash = ConvertKeyToHash(plainRoleName?.ToUpper());
            return string.Format(Constants.RowKeyConstants.FormatterIdentityRole, hash);
        }

        public string GeneratePartitionKeyIdentityRole(string plainRoleName)
        {
            string hash = ConvertKeyToHash(plainRoleName?.ToUpper());
            return hash.Substring(0, 1);
        }

        public string GenerateRowKeyIdentityUserClaim(string claimType, string claimValue)
        {
            string strTemp = $"{claimType?.ToUpper()}_{claimValue?.ToUpper()}";
            string hash = ConvertKeyToHash(strTemp);
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserClaim, hash);
        }

        public string GenerateRowKeyIdentityRoleClaim(string claimType, string claimValue)
        {
            string strTemp = $"{claimType?.ToUpper()}_{claimValue?.ToUpper()}";
            string hash = ConvertKeyToHash(strTemp);
            return string.Format(Constants.RowKeyConstants.FormatterIdentityRoleClaim, hash);
        }

        public string GenerateRowKeyIdentityUserToken(string loginProvider, string name)
        {
            string strTemp = $"{loginProvider?.ToUpper()}_{name?.ToUpper()}";
            string hash = ConvertKeyToHash(strTemp);
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserToken, hash);
        }

        public string ParsePartitionKeyIdentityRoleFromRowKey(string rowKey)
        {
            return rowKey.Substring(Constants.RowKeyConstants.PreFixIdentityRole.Length, 1);
        }

        public string GenerateRowKeyIdentityUserLogin(string loginProvider, string providerKey)
        {
            string strTemp = $"{loginProvider?.ToUpper()}_{providerKey?.ToUpper()}";
            string hash = ConvertKeyToHash(strTemp);
            return string.Format(Constants.RowKeyConstants.FormatterIdentityUserLogin, hash);
        }

        public double KeyVersion => 3.1;

        public static string ConvertKeyToHash(string input)
        {
            if (input != null)
            {
                using SHA1 sha = SHA1.Create();
                return GetHash(sha, input);
            }
            return null;
        }

        private static string GetHash(SHA1 shaHash, string input)
        {
            // Convert the input string to a byte array and compute the hash. 
            byte[] data = shaHash.ComputeHash(Encoding.Unicode.GetBytes(input));
            Debug.WriteLine($"Key Size before hash: {Encoding.UTF8.GetBytes(input).Length} bytes");

            // Create a new StringBuilder to collect the bytes 
            // and create a string.
            StringBuilder sBuilder = new StringBuilder(40);

            // Loop through each byte of the hashed data  
            // and format each one as a hexadecimal string. 
            foreach (var t in data)
            {
                sBuilder.Append(t.ToString("x2"));
            }
            Debug.WriteLine($"Key Size after hash: {data.Length} bytes");

            // Return the hexadecimal string. 
            return sBuilder.ToString();
        }
    }
}
