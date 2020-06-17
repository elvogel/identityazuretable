// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Azure.Cosmos.Table;
using ElCamino.AspNetCore.Identity.AzureTable.Helpers;
using ElCamino.AspNetCore.Identity.AzureTable.Model;

namespace ElCamino.AspNetCore.Identity.AzureTable
{
    public class RoleStore<TRole> : RoleStore<TRole, IdentityCloudContext>
    where TRole : Model.IdentityRole, new()
    {
        public RoleStore()
            : this(new IdentityCloudContext(), new DefaultKeyHelper())
        {
        }

        public RoleStore(IdentityCloudContext context, IKeyHelper keyHelper)
            : base(context, keyHelper)
        {
        }
    }

    public class RoleStore<TRole, TContext> : RoleStore<TRole, string, IdentityUserRole, IdentityRoleClaim, TContext>
        where TRole : Model.IdentityRole, new()
        where TContext : IdentityCloudContext, new()
    {
        public RoleStore(TContext context, IKeyHelper keyHelper) : base(context, keyHelper) { }

    }

    public class RoleStore<TRole, TKey, TUserRole, TRoleClaim, TContext> :
        RoleStoreBase<TRole, TKey, TUserRole, TRoleClaim>
        where TRole : IdentityRole<TKey, TUserRole>, new()
        where TUserRole : Model.IdentityUserRole<TKey>, new()
        where TRoleClaim : Model.IdentityRoleClaim<TKey>, new()
        where TContext : IdentityCloudContext, new()
        where TKey : IEquatable<TKey>
    {
        private bool _disposed;
        private CloudTable _roleTable;
        private readonly IdentityErrorDescriber _errorDescriber = new IdentityErrorDescriber();
        protected readonly IKeyHelper _keyHelper;

        public RoleStore(TContext context, IKeyHelper keyHelper) : base(new IdentityErrorDescriber())
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            _roleTable = context.RoleTable;
            _keyHelper = keyHelper;
        }

        public Task<bool> CreateTableIfNotExistsAsync()
         => Context.RoleTable.CreateIfNotExistsAsync();

        public override async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            ((IGenerateKeys)role).GenerateKeys(_keyHelper);

            // Create the TableOperation that inserts the role entity.
            TableOperation insertOperation = TableOperation.Insert(role);

            // Execute the insert operation.
            await _roleTable.ExecuteAsync(insertOperation, cancellationToken);
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            // Create the TableOperation that deletes the role entity.
            TableOperation deleteOperation = TableOperation.Delete(role);

            // Execute the insert operation.
            await _roleTable.ExecuteAsync(deleteOperation, cancellationToken);
            return IdentityResult.Success;
        }

        public new void Dispose()
        {
            base.Dispose();
            this.Dispose(true);
        }

        protected void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                Context?.Dispose();
                this._roleTable = null;
                this.Context = null;
                this._disposed = true;
            }
        }

        public override async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            TableOperation getOperation = TableOperation.Retrieve<TRole>(
                _keyHelper.ParsePartitionKeyIdentityRoleFromRowKey(roleId),
                roleId);

            var tresult = await _roleTable.ExecuteAsync(getOperation, cancellationToken);
            return (TRole) tresult.Result;
        }

        public override async Task<TRole> FindByNameAsync(string roleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            TableOperation getOperation = TableOperation.Retrieve<TRole>(
                _keyHelper.GeneratePartitionKeyIdentityRole(roleName),
                _keyHelper.GenerateRowKeyIdentityRole(roleName));

            TableResult tresult = await _roleTable.ExecuteAsync(getOperation, cancellationToken);
            return (TRole) tresult.Result;
        }


        public override async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (!(role is IGenerateKeys g) || g.PeekRowKey(_keyHelper).Equals(role.RowKey, StringComparison.Ordinal))
                return IdentityResult.Failed(_errorDescriber.InvalidRoleName(role.Name));
            var batch = new TableBatchOperation();
            var dRole = new DynamicTableEntity(role.PartitionKey, role.RowKey)
            {
                ETag = Constants.ETagWildcard, Timestamp = role.Timestamp
            };
            g.GenerateKeys(_keyHelper);
            //PartitionKey has to be the same to participate in a batch transaction.
            if (dRole.PartitionKey.Equals(role.PartitionKey))
            {
                batch.Add(TableOperation.Delete(dRole));
                batch.Add(TableOperation.Insert(role));
                await _roleTable.ExecuteBatchAsync(batch, cancellationToken);
            }
            else
            {
                await Task.WhenAll(
                    _roleTable.ExecuteAsync(TableOperation.Delete(dRole), cancellationToken),
                    _roleTable.ExecuteAsync(TableOperation.Insert(role), cancellationToken));
            }

            return IdentityResult.Success;

        }


        public override async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            var partitionFilter = TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, role.Id.ToString());

            var rowFilter1 = TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserToken);
            var rowFilter2 = TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.LessThan, "U_");
            var rowFilter = TableQuery.CombineFilters(rowFilter1, TableOperators.Or, rowFilter2);

            var filter = TableQuery.CombineFilters(partitionFilter, TableOperators.And, rowFilter);

            var tq = new TableQuery {FilterString = filter};
            var oc = new OperationContext();
            var trc = (TRoleClaim)Activator.CreateInstance(typeof(TRoleClaim));
            return
                (await _roleTable.ExecuteQueryAsync(tq))
                .Select(s =>
                {
                    if (trc == null) return null;
                    trc.ReadEntity(s.Properties, oc);
                    return trc;

                })
                .Select(w => w != null ? new Claim(w.ClaimType, w.ClaimValue) : null)
                .ToList();
        }

        public override async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var item = Activator.CreateInstance<TRoleClaim>();
            item.RoleId = role.Id;
            item.ClaimType = claim.Type;
            item.ClaimValue = claim.Value;
            ((IGenerateKeys)item).GenerateKeys(_keyHelper);

            await _roleTable.ExecuteAsync(TableOperation.Insert(item), cancellationToken);
        }

        public override async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (string.IsNullOrWhiteSpace(claim.Type))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(claim.Type));
            }

            TRoleClaim item = Activator.CreateInstance<TRoleClaim>();
            item.RoleId = role.Id;
            item.ClaimType = claim.Type;
            item.ClaimValue = claim.Value;
            item.ETag = Constants.ETagWildcard;
            ((IGenerateKeys)item).GenerateKeys(_keyHelper);

            await _roleTable.ExecuteAsync(TableOperation.Delete(item), cancellationToken);
        }

        public TContext Context { get; private set; }

        public override IQueryable<TRole> Roles => throw new NotImplementedException();
    }
}
