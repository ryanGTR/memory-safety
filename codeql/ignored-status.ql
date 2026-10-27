/**
 * @name Status-returning call result discarded
 * @description A static function that can return 0 (failure) is called
 *              as a statement, so its failure is silently treated as
 *              success. Shape of brotli CVE-2026-111497.
 * @kind problem
 * @id ryan/ignored-status
 * @problem.severity error
 */

import cpp

from FunctionCall fc, Function f
where
  f = fc.getTarget() and
  f.isStatic() and
  f.getUnspecifiedType() instanceof IntegralType and
  fc instanceof ExprInVoidContext and
  exists(ReturnStmt r | r.getEnclosingFunction() = f and r.getExpr().getValue() = "0")
select fc, "Result of " + f.getName() + " (can return 0 = failure) is discarded."
