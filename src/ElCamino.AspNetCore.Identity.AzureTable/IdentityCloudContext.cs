﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using System;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.Azure.Cosmos.Table;
// ReSharper disable ClassWithVirtualMembersNeverInherited.Global

namespace ElCamino.AspNetCore.Identity.AzureTable
{
    public class IdentityCloudContext : IDisposable
    {
        protected CloudTableClient _client;
        protected bool _disposed;
        protected IdentityConfiguration _config;
        protected CloudTable _roleTable;
        protected CloudTable _indexTable;
        protected CloudTable _userTable;

        public IdentityCloudContext() { }
        public IdentityCloudContext(IdentityConfiguration config)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }
            // ReSharper disable once VirtualMemberCallInConstructor
            Initialize(config);
        }

        protected virtual void Initialize(IdentityConfiguration config)
        {
            _config = config;
            _client = CloudStorageAccount.Parse(_config.StorageConnectionString).CreateCloudTableClient();
            _client.DefaultRequestOptions.PayloadFormat = TablePayloadFormat.Json;
            if (!string.IsNullOrWhiteSpace(_config.LocationMode))
            {
                if (Enum.TryParse<LocationMode>(_config.LocationMode, out var mode))
                {
                    _client.DefaultRequestOptions.LocationMode = mode;
                }
                else
                {
                    throw new ArgumentException(@"Invalid LocationMode defined in config. For more information on geo-replication location modes: https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.cosmos.table.tablerequestoptions.locationmode?view=azure-dotnet#Microsoft_Azure_Cosmos_Table_TableRequestOptions_LocationMode", nameof(config.LocationMode));
                }
            }
            _indexTable = _client.GetTableReference(FormatTableNameWithPrefix(!string.IsNullOrWhiteSpace(_config.IndexTableName) ? _config.IndexTableName : Constants.TableNames.IndexTable));
            _roleTable = _client.GetTableReference(FormatTableNameWithPrefix(!string.IsNullOrWhiteSpace(_config.RoleTableName) ? _config.RoleTableName : Constants.TableNames.RolesTable));
            _userTable = _client.GetTableReference(FormatTableNameWithPrefix(!string.IsNullOrWhiteSpace(_config.UserTableName) ? _config.UserTableName : Constants.TableNames.UsersTable));
        }

        ~IdentityCloudContext()
        {
            this.Dispose(false);
        }

        private string FormatTableNameWithPrefix(string baseTableName)
        {
            if(!string.IsNullOrWhiteSpace(_config.TablePrefix))
            {
                return $"{_config.TablePrefix}{baseTableName}";
            }
            return baseTableName;
        }

        public CloudTable RoleTable
        {
            get
            {
                ThrowIfDisposed();
                return _roleTable;
            }
        }

        public CloudTable UserTable
        {
            get
            {
                ThrowIfDisposed();
                return _userTable;
            }
        }

        public CloudTable IndexTable
        {
            get
            {
                ThrowIfDisposed();
                return _indexTable;
            }
        }

        public CloudTableClient Client
        {
            get
            {
                ThrowIfDisposed();
                return _client;
            }
        }

        private void ThrowIfDisposed()
        {
            if (this._disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }
        public void Dispose()
        {
            this.Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _client = null;
                _indexTable = null;
                _roleTable = null;
                _userTable = null;
                _disposed = true;
            }
        }
    }
}
