﻿// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using ElCamino.AspNetCore.Identity.AzureTable;
using Microsoft.Azure.Cosmos.Table;
using System;
using System.Collections.Generic;

namespace ElCamino.Identity.AzureTable.DataUtility
{
    public interface IMigration
    {
        TableQuery GetSourceTableQuery();

        bool UserWhereFilter(DynamicTableEntity d);

        void ProcessMigrate(IdentityCloudContext targetContext,
            IdentityCloudContext sourceContext,
            IList<DynamicTableEntity> sourceUserResults,
            int maxDegreesParallel,
            Action updateComplete = null,
            Action<string> updateError = null);
    }
}
