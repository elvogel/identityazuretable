// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
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
    public class UserOnlyStore<TUser>
        : UserOnlyStore<TUser, IdentityCloudContext> where TUser : Model.IdentityUser<string>, new()
    {
        public UserOnlyStore(IdentityCloudContext context, IKeyHelper keyHelper, IdentityConfiguration config) : base(context, keyHelper, config) { }

    }

    public class UserOnlyStore<TUser, TContext>
        : UserOnlyStore<TUser, TContext, string, IdentityUserClaim, IdentityUserLogin, IdentityUserToken>
        where TUser : Model.IdentityUser<string>, new()
        where TContext : IdentityCloudContext, new()
    {
        public UserOnlyStore(TContext context, IKeyHelper keyHelper, IdentityConfiguration config) : base(context, keyHelper, config) { }
    }

    public class UserOnlyStore<TUser, TContext, TKey, TUserClaim, TUserLogin, TUserToken> :
        UserStoreBase<TUser, TKey, TUserClaim, TUserLogin, TUserToken>
        , IDisposable
        where TUser : Model.IdentityUser<TKey>, new()
        where TKey : IEquatable<TKey>
        where TUserLogin : Model.IdentityUserLogin<TKey>, new()
        where TUserClaim : Model.IdentityUserClaim<TKey>, new()
        where TUserToken : Model.IdentityUserToken<TKey>, new()
        where TContext : IdentityCloudContext, new()
    {
        protected bool _disposed;

        protected CloudTable _userTable;
        protected CloudTable _indexTable;
        protected readonly IKeyHelper _keyHelper;

        private readonly IdentityConfiguration _config;

        public UserOnlyStore(TContext context, IKeyHelper keyHelper, IdentityConfiguration config) : base(new IdentityErrorDescriber())
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            _userTable = context.UserTable;
            _indexTable = context.IndexTable;
            _keyHelper = keyHelper;
            _config = config;
        }

        public override IQueryable<TUser> Users => throw new NotImplementedException();

        public virtual async Task<bool> CreateTablesIfNotExistsAsync()
        {
            Task<bool>[] tasks = new Task<bool>[]
                    {
                        _userTable.CreateIfNotExistsAsync(),
                        _indexTable.CreateIfNotExistsAsync(),
                    };
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return tasks.All(t => t.Result);
        }

        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claims == null) throw new ArgumentNullException(nameof(claims));

            BatchOperationHelper bop = new BatchOperationHelper();

            List<Task> tasks = new List<Task>();
            string userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            foreach (Claim c in claims)
            {
                bop.Add(TableOperation.Insert(CreateUserClaim(user, c)));
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.InsertOrReplace(CreateClaimIndex(userPartitionKey, c.Type, c.Value)), cancellationToken));
            }

            tasks.Add(bop.ExecuteBatchAsync(_userTable));
            await Task.WhenAll(tasks);
        }

        public virtual async Task AddClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claim == null) throw new ArgumentNullException(nameof(claim));

            var tasks = new List<Task>(2)
            {
                _userTable.ExecuteAsync(TableOperation.Insert(CreateUserClaim(user, claim))),
                _indexTable.ExecuteAsync(TableOperation.InsertOrReplace(
                    CreateClaimIndex(_keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id)), claim.Type,
                        claim.Value)))
            };


            await Task.WhenAll(tasks);
        }

        public override Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (login == null) throw new ArgumentNullException(nameof(login));

            TUserLogin item = CreateUserLogin(user, login);

            var index = CreateLoginIndex(_keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id)), item.LoginProvider, item.ProviderKey);

            return Task.WhenAll(_userTable.ExecuteAsync(TableOperation.Insert(item), cancellationToken)
                , _indexTable.ExecuteAsync(TableOperation.InsertOrReplace(index), cancellationToken));
        }

        public override async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            ((IGenerateKeys)user).GenerateKeys(_keyHelper);

            try
            {
                string userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
                List<Task> tasks = new List<Task>(2)
                {
                    _userTable.ExecuteAsync(TableOperation.Insert(user), cancellationToken),
                    _indexTable.ExecuteAsync(
                        TableOperation.Insert(CreateUserNameIndex(userPartitionKey, user.UserName)), cancellationToken)
                };

                if (!string.IsNullOrWhiteSpace(user.Email))
                {
                    var index = CreateEmailIndex(userPartitionKey, user.Email);
                    tasks.Add(_indexTable.ExecuteAsync(TableOperation.InsertOrReplace(index), cancellationToken));
                }

                await Task.WhenAll(tasks.ToArray());
                return IdentityResult.Success;
            }
            catch (AggregateException aggex)
            {
                aggex.Flatten();
                return IdentityResult.Failed(new IdentityError() { Code = "001", Description = "User Creation Failed." });
            }
        }

        public override async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            var tasks = new List<Task>(50);
            var userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            var userRows = await GetUserAggregateQueryAsync(userPartitionKey).ConfigureAwait(false);
            var dynamicTableEntities = userRows as DynamicTableEntity[] ?? userRows.ToArray();
            tasks.Add(DeleteAllUserRows(userPartitionKey, dynamicTableEntities));

            tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateUserNameIndex(userPartitionKey, user.UserName)),
                cancellationToken));

            var userAgg = MapUserAggregate(userPartitionKey, dynamicTableEntities);

            //Don't use the BatchHelper for login index table, partition keys are likely not the same
            //since they are based on LogonProvider and ProviderKey
            tasks.AddRange(userAgg.Logins.Select(userLogin =>
                _indexTable.ExecuteAsync(TableOperation.Delete(CreateLoginIndex(userPartitionKey, userLogin.LoginProvider, userLogin.ProviderKey)), cancellationToken)));

            foreach (var userClaim in userAgg.Claims)
            {
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateClaimIndex(userPartitionKey, userClaim.ClaimType, userClaim.ClaimValue)), cancellationToken));
            }

            if (!string.IsNullOrWhiteSpace(user.Email))
            {
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.Delete(CreateEmailIndex(userPartitionKey, user.Email)), cancellationToken));
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


        public new void Dispose()
        {
            base.Dispose();
            this.Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed || !disposing) return;
            Context?.Dispose();
            _indexTable = null;
            _userTable = null;
            Context = null;
            _disposed = true;
        }

        protected override async Task<TUserLogin> FindUserLoginAsync(TKey userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return await FindUserLoginAsync(ConvertIdToString(userId), loginProvider, providerKey);
        }

        protected async Task<TUserLogin> FindUserLoginAsync(string userId, string loginProvider, string providerKey)
        {
            string rowKey = _keyHelper.GenerateRowKeyIdentityUserLogin(loginProvider, providerKey);

            var tq = new TableQuery
            {
                TakeCount = 1,
                FilterString = TableQuery.CombineFilters(
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal,
                        userId),
                    TableOperators.And,
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, rowKey))
            };
            var log = (await _userTable.ExecuteQueryAsync(tq)).FirstOrDefault();
            return log == null ? null : MapTableEntity<TUserLogin>(log);
        }

        protected override async Task<TUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            string rowKey = _keyHelper.GenerateRowKeyIdentityUserLogin(loginProvider, providerKey);
            string partitionKey = _keyHelper.GeneratePartitionKeyIndexByLogin(loginProvider, providerKey);
            var loginQuery = GetUserIdByIndex(partitionKey, rowKey);

            var indexInfo = (await _indexTable.ExecuteQueryAsync(loginQuery).ConfigureAwait(false)).FirstOrDefault();
            if (indexInfo != null)
            {
                string userId = indexInfo.Properties["Id"].StringValue;
                return await FindUserLoginAsync(userId, loginProvider, providerKey);
            }

            return null;
        }

        /// <summary>
        /// Overridden for better performance.
        /// </summary>
        /// <param name="loginProvider"></param>
        /// <param name="providerKey"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            string rowKey = _keyHelper.GenerateRowKeyIdentityUserLogin(loginProvider, providerKey);
            string partitionKey = _keyHelper.GeneratePartitionKeyIndexByLogin(loginProvider, providerKey);
            var loginQuery = GetUserIdByIndex(partitionKey, rowKey);

            return GetUserAggregateAsync(loginQuery);
        }

        public override Task<TUser> FindByEmailAsync(string plainEmail, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            return this.GetUserAggregateAsync(FindByEmailQuery(plainEmail));
        }



        public async Task<IEnumerable<TUser>> FindAllByEmailAsync(string plainEmail)
        {
            this.ThrowIfDisposed();
            var users = await GetUsersAggregateByIndexQueryAsync(FindByEmailQuery(plainEmail), GetUserQueryAsync);
            return users.Where(user => _keyHelper.GenerateRowKeyUserEmail(plainEmail) == _keyHelper.GenerateRowKeyUserEmail(user.Email));
        }

        protected override Task<TUser> FindUserAsync(TKey userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return GetUserAsync(ConvertIdToString(userId));
        }

        protected TableQuery GetUserByRoleQuery(string plainRoleName)
             => GetUserIdsByIndex(_keyHelper.GenerateRowKeyIdentityUserRole(plainRoleName));

        protected TableQuery GetUserByClaimQuery(Claim claim)
         => GetUserIdsByIndex(_keyHelper.GenerateRowKeyIdentityUserClaim(claim.Type, claim.Value));

        protected TableQuery FindByEmailQuery(string plainEmail)
         => GetUserIdsByIndex(_keyHelper.GenerateRowKeyUserEmail(plainEmail));

        protected TableQuery FindByUserNameQuery(string userName)
            => GetUserIdsByIndex(_keyHelper.GenerateRowKeyUserName(userName));

        protected TableQuery GetUserIdByIndex(string partitionKey, string rowKey)
        {
            if (partitionKey == null) throw new ArgumentNullException(nameof(partitionKey));
            var tq = new TableQuery
            {
                TakeCount = 1,
                SelectColumns = new List<string> {"Id"},
                FilterString = TableQuery.CombineFilters(
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal,
                        partitionKey),
                    TableOperators.And,
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, rowKey))
            };
            return tq;
        }

        protected TableQuery GetUserIdsByIndex(string partitionKey)
        {
            var tq = new TableQuery
            {
                SelectColumns = new List<string>() {"Id"},
                FilterString = TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey),
                    QueryComparisons.Equal, partitionKey)
            };
            return tq;
        }

        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return GetUserAsync(_keyHelper.GenerateRowKeyUserId(userId));
        }

        public override Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var userId = FindByUserNameQuery(normalizedUserName);
            return GetUserAggregateAsync(userId);
        }

        protected async Task<TUserClaim> GetUserClaimAsync(TUser user, Claim claim)
        {
            var tr = await _userTable.ExecuteAsync(TableOperation.Retrieve<TUserClaim>(_keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id)),
                _keyHelper.GenerateRowKeyIdentityUserClaim(claim.Type, claim.Value)));
            return (TUserClaim) tr.Result;
        }


        public override async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            List<Claim> rClaims = new List<Claim>();

            TableQuery tq = new TableQuery();
            string partitionFilter =
                TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, user.PartitionKey);
            string rowFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserClaim),
                TableOperators.And,
                TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.LessThan, "D_"));
            tq.FilterString = TableQuery.CombineFilters(partitionFilter, TableOperators.And, rowFilter);
             foreach (var de in (await _userTable.ExecuteQueryAsync(tq)))
            {
                var tclaim = MapTableEntity<TUserClaim>(de);
                //1.7 Claim RowKey migration
                if (_keyHelper.GenerateRowKeyIdentityUserClaim(tclaim.ClaimType, tclaim.ClaimValue) == tclaim.RowKey)
                {
                    rClaims.Add(new Claim(tclaim.ClaimType, tclaim.ClaimValue));
                }
            }

            return rClaims;
        }

        protected T MapTableEntity<T>(DynamicTableEntity dte) where T : ITableEntity, new()
        {
            T t = new T()
            {
                ETag = dte.ETag,
                PartitionKey = dte.PartitionKey,
                RowKey = dte.RowKey,
                Timestamp = dte.Timestamp
            };
            t.ReadEntity(dte.Properties, new OperationContext());
            return t;
        }

        public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            TableQuery tq = new TableQuery();
            string partitionFilter =
                TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, user.PartitionKey);
            string rowFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserLogin),
                TableOperators.And,
                TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.LessThan, "M_"));
            tq.FilterString = TableQuery.CombineFilters(partitionFilter, TableOperators.And, rowFilter);
            return (await _userTable.ExecuteQueryAsync(tq)).Select(de => MapTableEntity<TUserLogin>(de)).Select(tul => new UserLoginInfo(tul.LoginProvider, tul.ProviderKey, tul.ProviderDisplayName)).ToList();
        }

        protected virtual async Task<TUser> GetUserAsync(string userId)
        {
            var tr = await _userTable.ExecuteAsync(TableOperation.Retrieve<TUser>(userId, userId));
            return (TUser) tr.Result;
        }

        protected Task<IEnumerable<DynamicTableEntity>> GetUserAggregateQueryAsync(string userId)
        {
            var tq = new TableQuery
            {
                FilterString =
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, userId)
            };

            return _userTable.ExecuteQueryAsync(tq);
        }

        protected async Task<IEnumerable<TUser>> GetUserAggregateQueryAsync(IEnumerable<string> userIds,
                Func<string, string> setFilterByUserId = null,
                Func<TUserClaim, bool> whereClaim = null)
        {
            const double pageSize = 50.0;
            var ids = userIds as string[] ?? userIds.ToArray();
            int pages = (int)Math.Ceiling(ids.Length / pageSize);
            var listTqs = new List<TableQuery>(pages);

            for (int currentPage = 1; currentPage <= pages; currentPage++)
            {
                var tempUserIds = currentPage > 1 ?
                    ids.Skip(((currentPage - 1) * (int)pageSize)).Take((int)pageSize) :
                    ids.Take((int)pageSize);

                TableQuery tq = new TableQuery();
                int i = 0;
                foreach (var tempUserId in tempUserIds)
                {

                    string temp =
                        TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey),
                            QueryComparisons.Equal, tempUserId);
                    if (setFilterByUserId != null)
                    {
                        temp = setFilterByUserId(tempUserId);
                    }

                    tq.FilterString = i > 0 ?
                        TableQuery.CombineFilters(tq.FilterString,
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
                return _userTable.ExecuteQueryAsync(q)
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

        protected virtual async Task<IEnumerable<TUser>> GetUserQueryAsync(IEnumerable<string> userIds)
        {
            const double pageSize = 50.0;
            var ids = userIds as string[] ?? userIds.ToArray();
            var pages = (int)Math.Ceiling(ids.Length / pageSize);
            var listTqs = new List<TableQuery>(pages);

            for (int currentPage = 1; currentPage <= pages; currentPage++)
            {
                var tempUserIds = currentPage > 1 ?
                    ids.Skip(((currentPage - 1) * (int)pageSize)).Take((int)pageSize) :
                    ids.Take((int)pageSize);

                TableQuery tq = new TableQuery();
                int tempUserCounter = 0;
                foreach (string tempUserId in tempUserIds)
                {

                    string temp = TableQuery.CombineFilters(
                        TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, tempUserId), TableOperators.And,
                        TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, tempUserId));
                    tq.FilterString = tempUserCounter > 0 ?
                        TableQuery.CombineFilters(tq.FilterString,
                            TableOperators.Or, temp) : temp;
                    tempUserCounter++;
                }
                listTqs.Add(tq);

            }

            ConcurrentBag<TUser> bag = new ConcurrentBag<TUser>();
#if DEBUG
            DateTime startUserAggTotal = DateTime.UtcNow;
#endif
            var tasks = listTqs.Select((q) =>
            {
                return _userTable.ExecuteQueryAsync(q)
                .ContinueWith((taskResults) =>
                {
                    foreach (var s in taskResults.Result)
                    {
                        bag.Add(MapTableEntity<TUser>(s));
                    }
                });

            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
#if DEBUG
            Debug.WriteLine("GetUserAggregateQuery (GetUserAggregateTotal): {0} seconds", (DateTime.UtcNow - startUserAggTotal).TotalSeconds);
#endif
            return bag;
        }

        protected (TUser User,
            IEnumerable<TUserClaim> Claims,
            IEnumerable<TUserLogin> Logins,
            IEnumerable<TUserToken> Tokens)
            MapUserAggregate(string userId, IEnumerable<DynamicTableEntity> userResults)
        {

            TUser user = default;
            IEnumerable<TUserClaim> claims = Enumerable.Empty<TUserClaim>();
            IEnumerable<TUserLogin> logins = Enumerable.Empty<TUserLogin>();
            IEnumerable<TUserToken> tokens = Enumerable.Empty<TUserToken>();

            var entities = userResults as DynamicTableEntity[] ?? userResults.ToArray();
            var vUser = entities.SingleOrDefault(u => u.RowKey.Equals(userId) && u.PartitionKey.Equals(userId));
            //var op = new OperationContext();

            if (vUser == null) return (null, claims, logins, tokens);
            {
                //User
                user = MapTableEntity<TUser>(vUser);

                //Claims
                claims = entities.Where(u => u.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserClaim)
                                             && u.PartitionKey.Equals(userId))
                    .Select(MapTableEntity<TUserClaim>);
                //Logins
                logins = entities.Where(u => u.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserLogin)
                                             && u.PartitionKey.Equals(userId))
                    .Select(MapTableEntity<TUserLogin>);

                //Tokens
                tokens = entities.Where(u => u.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserToken)
                                             && u.PartitionKey.Equals(userId))
                    .Select(MapTableEntity<TUserToken>);
            }
            return (user, claims, logins, tokens);
        }

        protected virtual async Task<TUser> GetUserAggregateAsync(TableQuery queryUser)
        {
            var user = (await _indexTable.ExecuteQueryAsync(queryUser)).FirstOrDefault();
            if (user == null) return default;
            var userId = user.Properties["Id"].StringValue;
            return await GetUserAsync(userId);

        }

        protected async Task<IEnumerable<TUser>> GetUsersAggregateByIndexQueryAsync(TableQuery queryUser, Func<IEnumerable<string>, Task<IEnumerable<TUser>>> getUserFunc)
        {
#if DEBUG
            DateTime startIndex = DateTime.UtcNow;
#endif
            ConcurrentBag<IEnumerable<TUser>> lUsers = new ConcurrentBag<IEnumerable<TUser>>();
            TableContinuationToken token = new TableContinuationToken();
            const int takeCount = 100;
            const int taskMax = 10;
            queryUser.TakeCount = takeCount;
            List<Task> taskBatch = new List<Task>(taskMax);

            async Task GetUsers(IEnumerable<string> ids)
            {
                lUsers.Add((await getUserFunc(ids)));
            }

            while (token != null)
            {
                var response = await _indexTable.ExecuteQuerySegmentedAsync(queryUser, token);
                var tempUserIds = response.Select(u => u.Properties["Id"].StringValue).Distinct();
                taskBatch.Add(GetUsers(tempUserIds));
                if (taskBatch.Count % taskMax == 0)
                {
                    await Task.WhenAll(taskBatch);
                    taskBatch.Clear();
                }
                token = response.ContinuationToken;
            }

            if (taskBatch.Count > 0)
            {
                await Task.WhenAll(taskBatch);
                taskBatch.Clear();
            }
#if DEBUG
            Debug.WriteLine("GetUsersAggregateByIndexQueryAsync (Index query): {0} seconds", (DateTime.UtcNow - startIndex).TotalSeconds);
#endif

            return lUsers.SelectMany(u => u);
        }

        public virtual async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claim == null) throw new ArgumentNullException(nameof(claim));

            // Claim ctor doesn't allow Claim.Value to be null. Need to allow string.empty.


            TUserClaim local = await GetUserClaimAsync(user, claim);
            if (local != null)
            {
                TableOperation deleteOperation = TableOperation.Delete(CreateUserClaim(user, claim));
                var tasks = new Task[]
                {
                    _indexTable.ExecuteAsync(TableOperation.Delete(
                        CreateClaimIndex(_keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id)), claim.Type, claim.Value))),
                    _userTable.ExecuteAsync(deleteOperation)
                };

                await Task.WhenAll(tasks);
            }

        }

        public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claim == null) throw new ArgumentNullException(nameof(claim));
            if (newClaim == null) throw new ArgumentNullException(nameof(newClaim));

            // Claim ctor doesn't allow Claim.Value to be null. Need to allow string.empty.
            BatchOperationHelper bop = new BatchOperationHelper();

            TUserClaim local = await GetUserClaimAsync(user, claim);
            List<Task> tasks = new List<Task>(3);
            string userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            if (local != null)
            {
                TableOperation deleteOperation = TableOperation.Delete(CreateUserClaim(user, claim));
                bop.Add(deleteOperation);
                tasks.Add(_indexTable.ExecuteAsync(
                    TableOperation.Delete(CreateClaimIndex(userPartitionKey, claim.Type, claim.Value)), cancellationToken));
            }
            TUserClaim item = CreateUserClaim(user, newClaim);

            bop.Add(TableOperation.Insert(item));
            tasks.Add(_indexTable.ExecuteAsync(
                TableOperation.InsertOrReplace(CreateClaimIndex(userPartitionKey, newClaim.Type, newClaim.Value)), cancellationToken));

            tasks.Add(bop.ExecuteBatchAsync(_userTable));

            await Task.WhenAll(tasks);
        }

        public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claims == null) throw new ArgumentNullException(nameof(claims));

            // Claim ctor doesn't allow Claim.Value to be null. Need to allow string.empty.
            var bop = new BatchOperationHelper();
            var tasks = new List<Task>();
            var userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            var userClaims = await GetClaimsAsync(user, cancellationToken);
            foreach (Claim claim in claims)
            {
                Claim local = (from uc in userClaims
                               where uc.Type == claim.Type && uc.Value == claim.Value
                               select uc).FirstOrDefault();
                if (local != null)
                {
                    TableOperation deleteOperation = TableOperation.Delete(CreateUserClaim(user, local));
                    bop.Add(deleteOperation);
                    tasks.Add(_indexTable.ExecuteAsync(
                        TableOperation.Delete(CreateClaimIndex(userPartitionKey, local.Type, local.Value)), cancellationToken));
                }
            }
            tasks.Add(bop.ExecuteBatchAsync(_userTable));
            await Task.WhenAll(tasks);
        }

        protected override TUserClaim CreateUserClaim(TUser user, Claim claim)
        {
            TUserClaim uc = base.CreateUserClaim(user, claim);
            ((IGenerateKeys)uc).GenerateKeys(_keyHelper);
            uc.PartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            uc.UserId = user.Id;
            uc.ETag = Constants.ETagWildcard;
            return uc;
        }

        protected override TUserLogin CreateUserLogin(TUser user, UserLoginInfo login)
        {
            TUserLogin ul = base.CreateUserLogin(user, login);
            ((IGenerateKeys)ul).GenerateKeys(_keyHelper);
            ul.PartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            ul.UserId = user.Id;
            ul.ETag = Constants.ETagWildcard;
            return ul;
        }

        public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            var userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            TUserLogin item = await FindUserLoginAsync(userPartitionKey, loginProvider, providerKey).ConfigureAwait(false);

            if (item != null)
            {
                var index = CreateLoginIndex(userPartitionKey, item.LoginProvider, item.ProviderKey);
                await Task.WhenAll(_indexTable.ExecuteAsync(TableOperation.Delete(index), cancellationToken),
                                    _userTable.ExecuteAsync(TableOperation.Delete(item), cancellationToken));
            }
        }

        public override async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            //Only remove the email if different
            //The UserManager calls UpdateAsync which will generate the new email index record
            if (!string.IsNullOrWhiteSpace(user.Email) && user.Email != email)
            {
                await DeleteEmailIndexAsync(_keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id)), user.Email).ConfigureAwait(false);
            }
            user.Email = email;
        }

        //Fixes deletes for non-unique emails for users.
        protected async Task DeleteEmailIndexAsync(string userId, string plainEmail)
        {
            var tq = new TableQuery
            {
                FilterString = TableQuery.CombineFilters(
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal,
                        _keyHelper.GenerateRowKeyUserEmail(plainEmail)),
                    TableOperators.And,
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, userId)),
                SelectColumns = new List<string>() {"Id"}
            };

            foreach (var de in (await _indexTable.ExecuteQueryAsync(tq)))
            {
                if (de.Properties["Id"].StringValue.Equals(userId, StringComparison.OrdinalIgnoreCase))
                {
                    await _indexTable.ExecuteAsync(TableOperation.Delete(de));
                }
            }
        }


        protected async Task DeleteAllUserRows(string userId, IEnumerable<DynamicTableEntity> userRows)
        {
            BatchOperationHelper deleteBatchHelper = new BatchOperationHelper();
            foreach (DynamicTableEntity delUserRow in userRows)
            {
                if (userId == delUserRow.PartitionKey)
                {
                    deleteBatchHelper.Add(TableOperation.Delete(delUserRow));
                }
            }

            await deleteBatchHelper.ExecuteBatchAsync(_userTable);
        }


        public override async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            string userPartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            List<Task> tasks = new List<Task>(3)
            {
                _userTable.ExecuteAsync(TableOperation.Replace(user), cancellationToken),
                _indexTable.ExecuteAsync(
                    TableOperation.InsertOrReplace(
                        CreateUserNameIndex(userPartitionKey, user.UserName)), cancellationToken)
            };

            if (!string.IsNullOrWhiteSpace(user.Email))
            {
                var indexEmail = CreateEmailIndex(userPartitionKey, user.Email);
                tasks.Add(_indexTable.ExecuteAsync(TableOperation.InsertOrReplace(indexEmail), cancellationToken));
            }

            try
            {
                await Task.WhenAll(tasks.ToArray());
                return IdentityResult.Success;
            }
            catch (AggregateException aggex)
            {
                aggex.Flatten();
                return IdentityResult.Failed(new IdentityError() { Code = "002", Description = "User Update Failed." });
            }

        }

        public TContext Context { get; private set; }

        protected IdentityUserIndex CreateClaimIndex(string userPartitionKey, string claimType, string claimValue)
        {
            return new IdentityUserIndex()
            {
                Id = userPartitionKey,
                PartitionKey = _keyHelper.GenerateRowKeyIdentityUserClaim(claimType, claimValue),
                RowKey = userPartitionKey,
                KeyVersion = _keyHelper.KeyVersion,
                ETag = Constants.ETagWildcard
            };
        }


        /// <summary>
        ///  Creates an role -> users index suitable for a crud operation
        /// </summary>
        /// <param name="userPartitionKey">Formatted UserId from the KeyHelper or IdentityUser.Id.ToString()</param>
        /// <param name="plainRoleName">Plain role name</param>
        /// <returns></returns>
        protected IdentityUserIndex CreateRoleIndex(string userPartitionKey, string plainRoleName)
        {
            return new IdentityUserIndex()
            {
                Id = userPartitionKey,
                PartitionKey = _keyHelper.GenerateRowKeyIdentityUserRole(plainRoleName),
                RowKey = userPartitionKey,
                KeyVersion = _keyHelper.KeyVersion,
                ETag = Constants.ETagWildcard
            };
        }

        /// <summary>
        /// Creates an email index suitable for a crud operation
        /// </summary>
        /// <param name="userid">Formatted UserId from the KeyHelper or IdentityUser.Id.ToString()</param>
        /// <param name="email">Plain email address.</param>
        /// <returns></returns>
        protected IdentityUserIndex CreateEmailIndex(string userid, string email)
        {
            return new IdentityUserIndex()
            {
                Id = userid,
                PartitionKey = _keyHelper.GenerateRowKeyUserEmail(email),
                RowKey = userid,
                KeyVersion = _keyHelper.KeyVersion,
                ETag = Constants.ETagWildcard
            };
        }

        /// <summary>
        /// Create an index for getting the user id based on his user name,
        /// Only used if EnableImmutableUserId = true
        /// </summary>
        /// <param name="userPartitionKey"></param>
        /// <param name="userName"></param>
        /// <returns></returns>
        protected IdentityUserIndex CreateUserNameIndex(string userPartitionKey, string userName)
        {
            return new IdentityUserIndex
            {
                Id = userPartitionKey,
                PartitionKey = _keyHelper.GenerateRowKeyUserName(userName),
                RowKey = userPartitionKey,
                KeyVersion = _keyHelper.KeyVersion,
                ETag = Constants.ETagWildcard
            };
        }

        protected IdentityUserIndex CreateLoginIndex(string userPartitionKey, string loginProvider, string providerKey)
        {
            return new IdentityUserIndex()
            {
                Id = userPartitionKey,
                PartitionKey = _keyHelper.GeneratePartitionKeyIndexByLogin(loginProvider, providerKey),
                RowKey = _keyHelper.GenerateRowKeyIdentityUserLogin(loginProvider, providerKey),
                KeyVersion = _keyHelper.KeyVersion,
                ETag = Constants.ETagWildcard
            };

        }

        public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            string getTableQueryFilterByUserId(string userId)
            {
                string rowFilter = TableQuery.CombineFilters(
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, userId),
                    TableOperators.Or,
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.RowKey), QueryComparisons.Equal, _keyHelper.GenerateRowKeyIdentityUserClaim(claim.Type, claim.Value)));

                string tqFilter = TableQuery.CombineFilters(
                    TableQuery.GenerateFilterCondition(nameof(TableEntity.PartitionKey), QueryComparisons.Equal, userId), TableOperators.And,
                    rowFilter);
                return tqFilter;
            }

            return (await this.GetUsersAggregateByIndexQueryAsync(GetUserByClaimQuery(claim), (userId) => {
                return GetUserAggregateQueryAsync(userId, setFilterByUserId: getTableQueryFilterByUserId, whereClaim: (uc) => uc.RowKey == _keyHelper.GenerateRowKeyIdentityUserClaim(claim.Type, claim.Value));

            })).ToList();
        }

        /// <summary>
        /// Base returns null as default, override returns string.empty as default
        /// </summary>
        /// <param name="user"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Id != null ? user.Id.ToString() : string.Empty);
        }

        protected override async Task<TUserToken> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            var tableOp = TableOperation.Retrieve<TUserToken>(_keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id)),
                _keyHelper.GenerateRowKeyIdentityUserToken(loginProvider, name));

            var result = await _userTable.ExecuteAsync(tableOp, cancellationToken);

            return (TUserToken) result.Result;
        }

        protected override TUserToken CreateUserToken(TUser user, string loginProvider, string name, string value)
        {
            TUserToken item = base.CreateUserToken(user, loginProvider, name, value);
            ((IGenerateKeys)item).GenerateKeys(_keyHelper);
            item.PartitionKey = _keyHelper.GenerateRowKeyUserId(ConvertIdToString(user.Id));
            item.UserId = user.Id;
            return item;
        }

        protected override async Task AddUserTokenAsync(TUserToken token)
        {
            await _userTable.ExecuteAsync(TableOperation.InsertOrReplace(token));
        }


        protected override async Task RemoveUserTokenAsync(TUserToken token)
        {
            await _userTable.ExecuteAsync(TableOperation.Delete(token));
        }



    }

}
