﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using ElCamino.AspNetCore.Identity.AzureTable;
using ElCamino.AspNetCore.Identity.AzureTable.Helpers;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.Azure.Cosmos.Table;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ElCamino.Identity.AzureTable.DataUtility
{
    public class UsersMigration : IMigration
    {
        private readonly IKeyHelper _keyHelper;
        public UsersMigration(IKeyHelper keyHelper)
        {
            _keyHelper = keyHelper;
        }

        public TableQuery GetSourceTableQuery()
        {
            //Get all User key records
            var tq = new TableQuery
            {
                SelectColumns = new List<string>() {"PartitionKey", "RowKey", "KeyVersion"}
            };
            string partitionFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserId),
                TableOperators.And,
                TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.LessThan, "V_"));
            string rowFilter = TableQuery.CombineFilters(
                TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.GreaterThanOrEqual, Constants.RowKeyConstants.PreFixIdentityUserId),
                TableOperators.And,
                TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.LessThan, "V_"));
            string keyVersionFilter = TableQuery.GenerateFilterConditionForDouble("KeyVersion", QueryComparisons.LessThan, _keyHelper.KeyVersion);
            string keysFilter = TableQuery.CombineFilters(partitionFilter, TableOperators.And, rowFilter);

            tq.FilterString = TableQuery.CombineFilters(keysFilter, TableOperators.And, keyVersionFilter);
            return tq;
        }

        public void ProcessMigrate(IdentityCloudContext targetContext, IdentityCloudContext sourceContext, IList<DynamicTableEntity> sourceUserKeysResults, int maxDegreesParallel, Action updateComplete = null, Action<string> updateError = null)
        {
            Parallel.ForEach(sourceUserKeysResults, new ParallelOptions() { MaxDegreeOfParallelism = maxDegreesParallel }, (dte) =>
            {
                try
                {
                    var sourceUserEntities = GetUserEntitiesBySourceId(dte.PartitionKey, sourceContext);
                    string targetUserId = _keyHelper.GenerateUserId();
                    var targetEntities = ConvertToTargetUserEntities(targetUserId, sourceUserEntities);
                    List<Task> mainTasks = new List<Task>(2);
                    List<Task> indexTasks = new List<Task>(100);
                    BatchOperationHelper batchOperation = new BatchOperationHelper();
                    targetEntities.targetUserEntities
                        .ForEach(targetUserRecord => batchOperation.Add(TableOperation.InsertOrReplace(targetUserRecord)));
                    mainTasks.Add(batchOperation.ExecuteBatchAsync(targetContext.UserTable));
                    targetEntities.targetUserIndexes
                        .ForEach(targetIndexRecord => indexTasks.Add(targetContext.IndexTable.ExecuteAsync(TableOperation.InsertOrReplace(targetIndexRecord))));
                    mainTasks.Add(Task.WhenAll(indexTasks));
                    Task.WhenAll(mainTasks).Wait();
                    updateComplete?.Invoke();
                }
                catch (AggregateException aggEx)
                {
                    updateError?.Invoke($"{dte.PartitionKey}-{dte.RowKey}\t{aggEx.Flatten().Message}");
                }
                catch (Exception ex)
                {
                    updateError?.Invoke($"{dte.PartitionKey}-{dte.RowKey}\t{ex.Message}");
                }

            });
        }

        private List<DynamicTableEntity> GetUserEntitiesBySourceId(string userPartitionKey, IdentityCloudContext sourcesContext)
        {
            List<DynamicTableEntity> results = new List<DynamicTableEntity>(1000);
            TableQuery tq = new TableQuery();
            string partitionKeyFilter = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, userPartitionKey);
            string keyVersionFilter = TableQuery.GenerateFilterConditionForDouble("KeyVersion", QueryComparisons.LessThan, _keyHelper.KeyVersion);
            tq.FilterString = TableQuery.CombineFilters(partitionKeyFilter, TableOperators.And, keyVersionFilter);
            TableContinuationToken token = new TableContinuationToken();
            while (token != null)
            {
                var r = sourcesContext.UserTable.ExecuteQuerySegmented(tq, token);
                token = r.ContinuationToken;
                results.AddRange(r.Results);
            }
            return results;
        }

        private (List<DynamicTableEntity> targetUserEntities, List<ITableEntity> targetUserIndexes) ConvertToTargetUserEntities(string userId, List<DynamicTableEntity> sourceUserEntities)
        {
            List<DynamicTableEntity> targetUserEntities = new List<DynamicTableEntity>(100);
            List<ITableEntity> targetUserIndexes = new List<ITableEntity>(100);
            foreach (DynamicTableEntity sourceEntity in sourceUserEntities)
            {
                if (sourceEntity.PartitionKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserId))
                {
                    string targetUserPartitionKey = _keyHelper.GenerateRowKeyUserId(userId);

                    //User record
                    if (sourceEntity.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserId))
                    {
                        //New User
                        //Add UserName Index
                        //Add Email Index
                        DynamicTableEntity tgtDte = new DynamicTableEntity(targetUserPartitionKey,
                            targetUserPartitionKey, Constants.ETagWildcard, sourceEntity.Properties)
                        {
                            Properties =
                            {
                                ["Id"] = new EntityProperty(userId),
                                ["KeyVersion"] = new EntityProperty(_keyHelper.KeyVersion)
                            }
                        };
                        targetUserEntities.Add(tgtDte);

                        //UserName index
                        tgtDte.Properties.TryGetValue("UserName", out EntityProperty userNameProperty);
                        if (userNameProperty != null)
                        {
                            string userNameKey = _keyHelper.GenerateRowKeyUserName(userNameProperty.StringValue);
                            IdentityUserIndex userNameIndex = new IdentityUserIndex()
                            {
                                Id = targetUserPartitionKey,
                                PartitionKey = userNameKey,
                                RowKey = targetUserPartitionKey,
                                KeyVersion = _keyHelper.KeyVersion,
                                ETag = Constants.ETagWildcard
                            };
                            targetUserIndexes.Add(userNameIndex);
                        }

                        //Email index - only if email exists
                        if (tgtDte.Properties.TryGetValue("Email", out EntityProperty emailProperty))
                        {
                            string emailKey = _keyHelper.GenerateRowKeyUserEmail(emailProperty.StringValue);
                            IdentityUserIndex emailIndex = new IdentityUserIndex()
                            {
                                Id = targetUserPartitionKey,
                                PartitionKey = emailKey,
                                RowKey = targetUserPartitionKey,
                                KeyVersion = _keyHelper.KeyVersion,
                                ETag = Constants.ETagWildcard
                            };
                            targetUserIndexes.Add(emailIndex);
                        }
                        continue;
                    }
                    //User Claim record
                    if (sourceEntity.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserClaim))
                    {
                        //New User Claim
                        //Add Claim Index
                        sourceEntity.Properties.TryGetValue("ClaimType", out EntityProperty claimTypeProperty);
                        string claimType = claimTypeProperty?.StringValue;
                        sourceEntity.Properties.TryGetValue("ClaimValue", out EntityProperty claimValueProperty);
                        string claimValue = claimValueProperty?.StringValue;

                        string targetUserRowKey = _keyHelper.GenerateRowKeyIdentityUserClaim(claimType, claimValue);
                        DynamicTableEntity tgtDte = new DynamicTableEntity(targetUserPartitionKey, targetUserRowKey,
                            Constants.ETagWildcard, sourceEntity.Properties)
                        {
                            Properties =
                            {
                                ["UserId"] = new EntityProperty(userId),
                                ["KeyVersion"] = new EntityProperty(_keyHelper.KeyVersion)
                            }
                        };
                        targetUserEntities.Add(tgtDte);

                        //Claim index
                        IdentityUserIndex claimIndex = new IdentityUserIndex()
                        {
                            Id = targetUserPartitionKey,
                            PartitionKey = targetUserRowKey,
                            RowKey = targetUserPartitionKey,
                            KeyVersion = _keyHelper.KeyVersion,
                            ETag = Constants.ETagWildcard
                        };
                        targetUserIndexes.Add(claimIndex);
                        continue;
                    }
                    //User Logon record
                    if (sourceEntity.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserLogin))
                    {
                        //New User Logon
                        //Add Logon Index
                        sourceEntity.Properties.TryGetValue("LoginProvider", out EntityProperty loginProviderProperty);
                        string loginProvider = loginProviderProperty?.StringValue;
                        sourceEntity.Properties.TryGetValue("ProviderKey", out EntityProperty providerKeyProperty);
                        string providerKey = providerKeyProperty?.StringValue;

                        string targetUserRowKey = _keyHelper.GenerateRowKeyIdentityUserLogin(loginProvider, providerKey);
                        DynamicTableEntity tgtDte = new DynamicTableEntity(targetUserPartitionKey, targetUserRowKey,
                            Constants.ETagWildcard, sourceEntity.Properties)
                        {
                            Properties =
                            {
                                ["UserId"] = new EntityProperty(userId),
                                ["KeyVersion"] = new EntityProperty(_keyHelper.KeyVersion)
                            }
                        };
                        targetUserEntities.Add(tgtDte);

                        //Logon index
                        IdentityUserIndex logonIndex = new IdentityUserIndex()
                        {
                            Id = targetUserPartitionKey,
                            PartitionKey = _keyHelper.GeneratePartitionKeyIndexByLogin(loginProvider, providerKey),
                            RowKey = _keyHelper.GenerateRowKeyIdentityUserLogin(loginProvider, providerKey),
                            KeyVersion = _keyHelper.KeyVersion,
                            ETag = Constants.ETagWildcard
                        };
                        targetUserIndexes.Add(logonIndex);
                        continue;
                    }
                    //User Role record
                    if (sourceEntity.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserRole))
                    {
                        //New User Role
                        //Add Role Index
                        sourceEntity.Properties.TryGetValue("RoleName", out EntityProperty roleNameProperty);
                        string roleName = roleNameProperty?.StringValue;

                        string targetUserRowKey = _keyHelper.GenerateRowKeyIdentityUserRole(roleName);
                        DynamicTableEntity tgtDte = new DynamicTableEntity(targetUserPartitionKey, targetUserRowKey,
                            Constants.ETagWildcard, sourceEntity.Properties)
                        {
                            Properties =
                            {
                                ["UserId"] = new EntityProperty(userId),
                                ["KeyVersion"] = new EntityProperty(_keyHelper.KeyVersion)
                            }
                        };
                        targetUserEntities.Add(tgtDte);

                        //Role index
                        IdentityUserIndex roleIndex = new IdentityUserIndex()
                        {
                            Id = targetUserPartitionKey,
                            PartitionKey = targetUserRowKey,
                            RowKey = targetUserPartitionKey,
                            KeyVersion = _keyHelper.KeyVersion,
                            ETag = Constants.ETagWildcard
                        };
                        targetUserIndexes.Add(roleIndex);
                        continue;
                    }
                    //User Token record
                    if (sourceEntity.RowKey.StartsWith(Constants.RowKeyConstants.PreFixIdentityUserToken))
                    {
                        //New User Token
                        sourceEntity.Properties.TryGetValue("LoginProvider", out EntityProperty loginProviderProperty);
                        string loginProvider = loginProviderProperty?.StringValue;
                        sourceEntity.Properties.TryGetValue("TokenName", out EntityProperty tokenNameProperty);
                        string tokenName = tokenNameProperty?.StringValue;

                        string targetUserRowKey = _keyHelper.GenerateRowKeyIdentityUserToken(loginProvider, tokenName);
                        DynamicTableEntity tgtDte = new DynamicTableEntity(targetUserPartitionKey, targetUserRowKey,
                            Constants.ETagWildcard, sourceEntity.Properties)
                        {
                            Properties =
                            {
                                ["UserId"] = new EntityProperty(userId),
                                ["KeyVersion"] = new EntityProperty(_keyHelper.KeyVersion)
                            }
                        };
                        targetUserEntities.Add(tgtDte);
                    }
                }
            }
            return (targetUserEntities, targetUserIndexes);
        }

        public bool UserWhereFilter(DynamicTableEntity d)
        {
            return true;
        }
    }
}
