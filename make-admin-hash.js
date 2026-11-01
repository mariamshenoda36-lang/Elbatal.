import crypto from "node:crypto";
import readline from "node:readline";
const rl=readline.createInterface({input:process.stdin,output:process.stdout});
rl.question("اكتب رمز الإدارة الجديد (لن يتم حفظه كنص في ملفات الموقع): ", code=>{
  if(!/^[0-9]{6,}$/.test(code)){console.error("استخدم 6 أرقام على الأقل.");process.exit(1);}
  const salt=crypto.randomBytes(16).toString("hex");
  const hash=crypto.scryptSync(code,salt,64).toString("hex");
  console.log("\nضع السطر التالي في متغير البيئة ADMIN_CODE_HASH:\n"+salt+":"+hash+"\n");
  rl.close();
});
