// MIT License Copyright 2020 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Microsoft.Azure.Cosmos.Table
{
    public static class AzureSdkHelper
    {
        public static Task<IEnumerable<DynamicTableEntity>> ExecuteQueryAsync(this CloudTable ct, TableQuery tq)
        {
            return Task.Run(() => ExecuteQuery(ct, tq));
        }
        public static IEnumerable<DynamicTableEntity> ExecuteQuery(this CloudTable ct, TableQuery tq)
        {
            TableContinuationToken t = new TableContinuationToken();
#if DEBUG
            int iCounter = 0;
#endif
            while (t != null)
            {
                var segment = ct.ExecuteQuerySegmented(tq, t);
                foreach (var result in segment.Results)
                {
#if DEBUG
                    iCounter++;
#endif
                    yield return result;
                }
                t = segment.ContinuationToken;
            }
#if DEBUG

            Debug.WriteLine("ExecuteQuery: (Count): {0}", iCounter);
            Debug.WriteLine("ExecuteQuery (Query): " + tq.FilterString);
#endif
        }
    }
}
