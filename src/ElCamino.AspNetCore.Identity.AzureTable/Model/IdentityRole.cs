﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using System.Collections.Generic;
using System;
using Microsoft.Azure.Cosmos.Table;

namespace ElCamino.AspNetCore.Identity.AzureTable.Model
{
    public class IdentityRole : IdentityRole<string, IdentityUserRole>, IGenerateKeys
    {
        public IdentityRole()
        { }

        /// <summary>
        /// Generates Row and Id keys.
        /// Partition key is equal to the UserId
        /// </summary>
        public void GenerateKeys(IKeyHelper keyHelper)
        {
            RowKey = PeekRowKey(keyHelper);
            PartitionKey = keyHelper.GeneratePartitionKeyIdentityRole(Name);
            KeyVersion = keyHelper.KeyVersion;
        }

        /// <summary>
        /// Generates the RowKey without setting it on the object.
        /// </summary>
        /// <returns></returns>
        public string PeekRowKey(IKeyHelper keyHelper)
        {
            return keyHelper.GenerateRowKeyIdentityRole(Name);
        }

        public double KeyVersion { get; set; }

        public IdentityRole(string roleName)
            : this()
        {
            base.Name = roleName;
        }

        [IgnoreProperty]
        public override string Id
        {
            get => RowKey;
            set => RowKey = value;
        }
    }

    public class IdentityRole<TKey, TUserRole> : Microsoft.AspNetCore.Identity.IdentityRole<TKey>, ITableEntity
        where TKey : IEquatable<TKey>
        where TUserRole : IdentityUserRole<TKey>
    {
        private readonly ICollection<TUserRole> _users;
        public string PartitionKey { get; set; }
        public string RowKey { get; set; }
        public DateTimeOffset Timestamp { get; set; }
        public string ETag { get; set; }

        public virtual void ReadEntity(IDictionary<string, EntityProperty> properties, OperationContext operationContext)
        {
            TableEntity.ReadUserObject(this, properties, operationContext);
        }

        public virtual IDictionary<string, EntityProperty> WriteEntity(OperationContext operationContext)
        {
            return TableEntity.WriteUserObject(this, operationContext);
        }

        public IdentityRole()
        {
            _users = new List<TUserRole>();
        }

        [IgnoreProperty]
        public override TKey Id { get; set; }


        [IgnoreProperty]
        public ICollection<TUserRole> Users => _users;
    }
}
