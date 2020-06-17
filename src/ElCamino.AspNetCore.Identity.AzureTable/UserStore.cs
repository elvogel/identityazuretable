// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Azure.Cosmos.Table;
using ElCamino.AspNetCore.Identity.AzureTable.Model;

namespace ElCamino.AspNetCore.Identity.AzureTable
{
    public class UserStore<TUser, TContext> : UserStore<TUser, Model.IdentityRole, string,
        IdentityUserLogin, IdentityUserRole, IdentityUserClaim, IdentityUserToken, TContext>
        where TUser : Model.IdentityUser<string>, new()
       where TContext : IdentityCloudContext, new()
    {
        public UserStore(TContext context, IKeyHelper keyHelper, IdentityConfiguration config) :
            base(context, keyHelper, config) { }
    }
    /// <summary>
    /// Supports as slimmer, trimmer, IdentityUser
    /// Use this for keep inline with v3 core identity base user model.
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TRole"></typeparam>
    /// <typeparam name="TContext"></typeparam>
    public class UserStore<TUser, TRole, TContext> : UserStore<TUser, TRole, string, IdentityUserLogin,
            IdentityUserRole, IdentityUserClaim, IdentityUserToken, TContext> where TUser : Model.IdentityUser<string>, new()
        where TRole : IdentityRole<string, IdentityUserRole>, new()
        where TContext : IdentityCloudContext, new()
    {
        public UserStore(TContext context, IKeyHelper keyHelper, IdentityConfiguration config) : base(context, keyHelper, config) { }
    }

    public class UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim, TUserToken, TContext> :
        UserOnlyStore<TUser, TContext, TKey, TUserClaim, TUserLogin, TUserToken>
        , IUserRoleStore<TUser> where TUser : Model.IdentityUser<TKey>, new()
        where TRole : IdentityRole<TKey, TUserRole>, new()
        where TKey : IEquatable<TKey>
        where TUserLogin : Model.IdentityUserLogin<TKey>, new()
        where TUserRole : Model.IdentityUserRole<TKey>, new()
        where TUserClaim : Model.IdentityUserClaim<TKey>, new()
        where TUserToken : Model.IdentityUserToken<TKey>, new()
        where TContext : IdentityCloudContext, new()
    {
        protected CloudTable _roleTable;

        public UserStore(TContext context, IKeyHelper keyHelper, IdentityConfiguration config) : base(context, keyHelper, config)
        {
            this._roleTable = context.RoleTable;
        }

        public override async Task<bool> CreateTablesIfNotExistsAsync()
        {
            Task<bool>[] tasks =
                new Task<bool>[]
                {
                    base.CreateTablesIfNotExistsAsync(),
                    _roleTable.CreateIfNotExistsAsync(),
                };
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return tasks.All(t => t.Result);
        }

        public virtual async Task AddToRoleAsync(TUser user, string roleName,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(roleName));
            }

            var roleT = new TRole {Name = roleName};
            ((IGenerateKeys)roleT).GenerateKeys(_keyHelper);


            var userToRole = new TUserRole
            {
                PartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id)),
                RoleId = roleT.Id,
                RoleName = roleT.Name,
                UserId = user.Id
            };
            TUserRole item = userToRole;

            ((IGenerateKeys)item).GenerateKeys(_keyHelper);

            roleT.Users.Add(item);

            var tasks = new List<Task>(2)
            {
                _userTable.ExecuteAsync(TableOperation.Insert(item), cancellationToken),
                _indexTable.ExecuteAsync(
                    TableOperation.InsertOrReplace(CreateRoleIndex(userToRole.PartitionKey, roleName)),
                    cancellationToken)
            };


            await Task.WhenAll(tasks);
        }

        public virtual async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (EqualityComparer<TKey>.Default.Equals(user.Id, default))
            {
                throw new ArgumentNullException(nameof(user.Id));
            }

            const string roleName = "RoleName";
            string userId = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            // Changing to a live query to mimic EF UserStore in Identity 3.0
            TableQuery tq = new TableQuery();

            string rowFilter =
                TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserRole);

            tq.FilterString = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, userId),
                TableOperators.And,
                rowFilter);
            tq.SelectColumns = new List<string>() { roleName };
            var userRoles =
                (await _userTable.ExecuteQueryAsync(tq))
                .Where(w => w.Properties[roleName] != null)
                .Select(d => d.Properties[roleName].StringValue)
                .Where(di => !string.IsNullOrWhiteSpace(di));

            var roles = userRoles as string[] ?? userRoles.ToArray();
            int userRoleTotalCount = roles.Length;
            if (userRoleTotalCount > 0)
            {
                const double pageSize = 10d;
                double maxPages = Math.Ceiling(userRoleTotalCount / pageSize);

                List<Task<List<string>>> tasks = new List<Task<List<string>>>((int)maxPages);

                for (int iPageIndex = 0; iPageIndex < maxPages; iPageIndex++)
                {
                    int skip = (int)(iPageIndex * pageSize);
                    IEnumerable<string> userRolesTemp = skip > 0 ? roles.Skip(skip).Take((int)pageSize) :
                        roles.Take((int)pageSize);

                    string queryTemp = string.Empty;
                    int iRoleCounter = 0;
                    foreach (var urt in userRolesTemp)
                    {
                        queryTemp = iRoleCounter == 0 ? BuildRoleQuery(urt) :
                            TableQuery.CombineFilters(queryTemp, TableOperators.Or,
                                BuildRoleQuery(urt));
                        iRoleCounter++;
                    }
                    const string rName = "Name";
                    var tqRoles = new TableQuery
                    {
                        FilterString = queryTemp, SelectColumns = new List<string>() {rName}
                    };
                    tasks.Add(
                        _roleTable.ExecuteQueryAsync(tqRoles)
                        .ContinueWith((t) => {
                            return t.Result.Where(w => w.Properties[rName] != null)
                            .Select(d => d.Properties[rName].StringValue)
                            .Where(di => !string.IsNullOrWhiteSpace(di))
                            .ToList();
                        }, cancellationToken)
                    );
                }
                await Task.WhenAll(tasks).ConfigureAwait(false);
                return tasks.Select(s => s.Result).SelectMany(m => m).ToList();
            }

            return new List<string>();
        }
        public string BuildRoleQuery(string normalizedRoleName)
        {
            string rowFilter =
                TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey),
                QueryComparisons.Equal,
                _keyHelper.GenerateRowKeyIdentityRole(normalizedRoleName));

            return TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey),
                QueryComparisons.Equal, _keyHelper.GeneratePartitionKeyIdentityRole(normalizedRoleName)),
                TableOperators.And,
                rowFilter);
        }

        public virtual async Task<IList<TUser>> GetUsersInRoleAsync(string roleName,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(roleName));
            }

            if (!await RoleExistsAsync(roleName)) return new List<TUser>();

            string GetTableQueryFilterByUserId(string userId)
            {
                string rowFilter = TableQuery.CombineFilters(TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, userId), TableOperators.Or, TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, _keyHelper.GenerateRowKeyIdentityUserRole(roleName)));

                string tqFilter = TableQuery.CombineFilters(TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, userId), TableOperators.And, rowFilter);
                return tqFilter;
            }


            return (await this.GetUsersAggregateByIndexQueryAsync(GetUserByRoleQuery(roleName), (userId) => {
                return GetUserAggregateQueryAsync(userId, GetTableQueryFilterByUserId,
                    whereClaim: null, whereRole: (ur) => ur.RowKey == _keyHelper.GenerateRowKeyIdentityUserRole(roleName));

            })).ToList();

        }

        public virtual async Task<bool> IsInRoleAsync(TUser user, string roleName,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(roleName));
            }

            var userId = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            // Changing to a live query to mimic EF UserStore in Identity 3.0
            var tq = new TableQuery();

            string rowFilter =
                TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, _keyHelper.GenerateRowKeyIdentityUserRole(roleName));

            tq.FilterString = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, userId),
                TableOperators.And,
                rowFilter);
            tq.SelectColumns = new List<string>() { nameof(TableEntity.RowKey) };
            tq.TakeCount = 1;
            var tasks = new[]
            {
                Task.FromResult(_userTable.ExecuteQuery(tq).Any()),
                RoleExistsAsync(roleName)
            };

            await Task.WhenAll(tasks);

            return tasks.All(t => t.Result);
        }

        public async Task<bool> RoleExistsAsync(string roleName)
        {
            var tqRoles = new TableQuery
            {
                FilterString = BuildRoleQuery(roleName), SelectColumns = new List<string>() {"Name"}, TakeCount = 1
            };
            return (await _roleTable.ExecuteQueryAsync(tqRoles)).Any();
        }

        public virtual async Task RemoveFromRoleAsync(TUser user, string roleName,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(roleName));

            string userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            var tresult = await _userTable.ExecuteAsync(TableOperation.Retrieve<TUserRole>(
                userPartitionKey, _keyHelper.GenerateRowKeyIdentityRole(roleName)), cancellationToken)
                .ConfigureAwait(false);

            if (tresult.Result is TUserRole item)
            {
                TableOperation deleteOperation = TableOperation.Delete(item);

                await Task.WhenAll(
                   _userTable.ExecuteAsync(deleteOperation, cancellationToken),
                    _indexTable.ExecuteAsync(TableOperation.Delete(CreateRoleIndex(userPartitionKey, roleName)), cancellationToken)
                );

            }
        }

        protected async Task<IEnumerable<TUser>> GetUserAggregateQueryAsync(IEnumerable<string> userIds,
        Func<string, string> setFilterByUserId = null,
        Func<TUserRole, bool> whereRole = null,
        Func<TUserClaim, bool> whereClaim = null)
        {
            const double pageSize = 50.0;
            var ids = userIds as string[] ?? userIds.ToArray();
            int pages = (int)Math.Ceiling(ids.Length / pageSize);
            List<TableQuery> listTqs = new List<TableQuery>(pages);

            for (int currentPage = 1; currentPage <= pages; currentPage++)
            {
                var tempUserIds = currentPage > 1 ?
                    ids.Skip(((currentPage - 1) * (int)pageSize)).Take((int)pageSize) :
                    ids.Take((int)pageSize);

                TableQuery tq = new TableQuery();
                int i = 0;
                foreach (var tempUserId in tempUserIds)
                {

                    var temp = TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey),
                        QueryComparisons.Equal, tempUserId);
                    if (setFilterByUserId != null)
                    {
                        temp = setFilterByUserId(tempUserId);
                    }

                    tq.FilterString = i > 0 ? TableQuery.CombineFilters(tq.FilterString,
                        TableOperators.Or, temp) : temp;
                    i++;
                }
                listTqs.Add(tq);

            }

            ConcurrentBag<TUser> bag = new ConcurrentBag<TUser>();
#if DEBUG
            DateTime startUserAggTotal = DateTime.UtcNow;
#endif
            var tasks = listTqs.Select((q) =>
            {
                return
                _userTable.ExecuteQueryAsync(q)
                     .ContinueWith((taskResults) =>
                     {
                         //ContinueWith returns completed task. Calling .Result is safe here.

                         foreach (var s in taskResults.Result.GroupBy(g => g.PartitionKey))
                         {
                             var userAgg = MapUserAggregate(s.Key, s);
                             bool addUser = true;
                             if (whereClaim != null)
                             {
                                 if (!userAgg.Claims.Any(whereClaim))
                                 {
                                     addUser = false;
                                 }
                             }
                             if (whereRole != null)
                             {
                                 if (!userAgg.Roles.Any(whereRole))
                                 {
                                     addUser = false;
                                 }
                             }
                             if (addUser)
                             {
                                 bag.Add(userAgg.User);
                             }
                         }
                     });

            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
#if DEBUG
            Debug.WriteLine("GetUserAggregateQuery (GetUserAggregateTotal): {0} seconds", (DateTime.UtcNow - startUserAggTotal).TotalSeconds);
            Debug.WriteLine("GetUserAggregateQuery (Return Count): {0} userIds", bag.Count);
#endif
            return bag;
        }

        protected (TUser User,
            IEnumerable<TUserRole> Roles,
            IEnumerable<TUserClaim> Claims,
            IEnumerable<TUserLogin> Logins,
            IEnumerable<TUserToken> Tokens)
        MapUserAggregate(string userId,
            IEnumerable<DynamicTableEntity> userResults,
            Func<TUserRole, bool> whereRole = null,
            Func<TUserClaim, bool> whereClaim = null)
        {

            TUser user;
            IEnumerable<TUserRole> roles = Enumerable.Empty<TUserRole>();
            IEnumerable<TUserClaim> claims = Enumerable.Empty<TUserClaim>();
            IEnumerable<TUserLogin> logins = Enumerable.Empty<TUserLogin>();
            IEnumerable<TUserToken> tokens = Enumerable.Empty<TUserToken>();

            var results = userResults as DynamicTableEntity[] ?? userResults.ToArray();
            var vUser = results.SingleOrDefault(u => u.RowKey.Equals(userId) && u.PartitionKey.Equals(userId));
            //var op = new OperationContext();

            if (vUser == null) return (null, roles, claims, logins, tokens);
            {
                //User
                user = MapTableEntity<TUser>(vUser);

                //Roles
                roles = results.Where(u => u.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserRole)
                                           && u.PartitionKey.Equals(userId))
                    .Select(MapTableEntity<TUserRole>);
                //Claims
                claims = results.Where(u => u.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserClaim)
                                            && u.PartitionKey.Equals(userId))
                    .Select(MapTableEntity<TUserClaim>);
                //Logins
                logins = results.Where(u => u.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserLogin)
                                            && u.PartitionKey.Equals(userId))
                    .Select(MapTableEntity<TUserLogin>);

                //Tokens
                tokens = results.Where(u => u.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserToken)
                                            && u.PartitionKey.Equals(userId))
                    .Select(MapTableEntity<TUserToken>);
            }
            return (user, roles, claims, logins, tokens);
        }

        public override async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            List<Task> tasks = new List<Task>(50);
            string userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            var userRows = await
                GetUserAggregateQueryAsync(userPartitionKey).ConfigureAwait(false);
            var rows = userRows as DynamicTableEntity[] ?? userRows.ToArray();
            tasks.Add(DeleteAllUserRows(userPartitionKey, rows));

            tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateUserNameIndex(userPartitionKey, user.UserName)),
                cancellationToken));

            var userAgg = MapUserAggregate(userPartitionKey, rows);

            //Don't use the BatchHelper for login index table, partition keys are likely not the same
            //since they are based on LogonProvider and ProviderKey
            foreach (var userLogin in userAgg.Logins)
            {
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateLoginIndex(userPartitionKey,
                    userLogin.LoginProvider, userLogin.ProviderKey)), cancellationToken));
            }

            foreach (var userRole in userAgg.Roles)
            {
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateRoleIndex(userPartitionKey,
                    userRole.RoleName)), cancellationToken));
            }

            foreach (var userClaim in userAgg.Claims)
            {
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateClaimIndex(userPartitionKey,
                    userClaim.ClaimType, userClaim.ClaimValue)), cancellationToken));
            }

            if (!string.IsNullOrWhiteSpace(user.Email))
            {
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateEmailIndex(userPartitionKey,
                    user.Email)), cancellationToken));
            }

            try
            {
                await Task.WhenAll(tasks.ToArray());
                return IdentityResult.Success;
            }
            catch (AggregateException aggex)
            {
                aggex.Flatten();
                return IdentityResult.Failed(new IdentityError() { Code = "003", Description = "Delete user failed." });
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                this._roleTable = null;
            }
            base.Dispose(disposing);
        }
    }

}
