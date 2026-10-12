package executor

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDatabaseRestoreDefinersKeepDumpObjectsAndLiteralData(t *testing.T) {
	for _, fixture := range []struct{ name, sql, want string }{
		{"view", "CREATE DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW v AS SELECT 1;", "CREATE DEFINER=CURRENT_USER SQL SECURITY DEFINER VIEW v AS SELECT 1;"},
		{"routine", "DELIMITER ;;\nCREATE DEFINER = 'root' @ '%' PROCEDURE p() BEGIN SELECT 1; SELECT 2; END;;\nDELIMITER ;\n", "DELIMITER ;;\nCREATE DEFINER=CURRENT_USER PROCEDURE p() BEGIN SELECT 1; SELECT 2; END;;\nDELIMITER ;\n"},
		{"trigger", "/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER t BEFORE INSERT ON x FOR EACH ROW SET NEW.id=1 */;", "/*!50003 CREATE*/ /*!50017 DEFINER=CURRENT_USER*/ /*!50003 TRIGGER t BEFORE INSERT ON x FOR EACH ROW SET NEW.id=1 */;"},
		{"mariadb_event", "/*M!50106 CREATE DEFINER=`root`@`localhost` EVENT e ON SCHEDULE EVERY 1 DAY DO SELECT 1 */;", "/*M!50106 CREATE DEFINER=CURRENT_USER EVENT e ON SCHEDULE EVERY 1 DAY DO SELECT 1 */;"},
		{"current_user", "CREATE DEFINER=CURRENT_USER() VIEW v AS SELECT 1;", "CREATE DEFINER=CURRENT_USER VIEW v AS SELECT 1;"},
		{"literal", `INSERT INTO data VALUES ('DEFINER=root@localhost','a\'b','x; y', 'value');`, `INSERT INTO data VALUES ('DEFINER=root@localhost','a\'b','x; y', 'value');`},
		{"comments", "-- DEFINER=root@localhost\n# DEFINER=root@localhost\n/* DEFINER=root@localhost */ SELECT 1;", "-- DEFINER=root@localhost\n# DEFINER=root@localhost\n/* DEFINER=root@localhost */ SELECT 1;"},
		{"quoted_identifier", "SELECT `DEFINER`, 'DEFINER=root@localhost';", "SELECT `DEFINER`, 'DEFINER=root@localhost';"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := rebindDatabaseRestoreDefiners(&out, strings.NewReader(fixture.sql)); err != nil {
				t.Fatal(err)
			}
			if out.String() != fixture.want {
				t.Fatalf("got=%q want=%q", out.String(), fixture.want)
			}
		})
	}
}

func TestDatabaseRestoreDefinersFailOnIncompleteSyntaxAndWrites(t *testing.T) {
	for _, sql := range []string{"CREATE DEFINER='root VIEW v;", "CREATE DEFINER= VIEW v;", "CREATE DEFINER=root VIEW v;", "CREATE DEFINER=`" + strings.Repeat("x", 1025) + "`@localhost VIEW v;"} {
		if err := rebindDatabaseRestoreDefiners(io.Discard, strings.NewReader(sql)); err == nil {
			t.Fatalf("accepted malformed definer=%q", sql)
		}
	}
	if err := rebindDatabaseRestoreDefiners(databaseRestoreRejectWriter{}, strings.NewReader("CREATE DEFINER=root@localhost VIEW v AS SELECT 1;")); err == nil {
		t.Fatal("ignored destination failure")
	}
}

type databaseRestoreRejectWriter struct{}

func (databaseRestoreRejectWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture write failure")
}

func TestDatabaseRestoreBufferedDefinersPreserveLockAndDelimiter(t *testing.T) {
	sql := "USE original_db;\nCREATE TABLE x (id int);\nLOCK TABLES x WRITE;\nUNLOCK TABLES;\nDELIMITER ;;\nCREATE DEFINER=`root`@`localhost` PROCEDURE p() BEGIN SELECT 1; SELECT 2; END;;\nDELIMITER ;\n"
	var out bytes.Buffer
	if err := filterRestoreSQLBuffered(&out, strings.NewReader(sql)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LOCK TABLES x WRITE;", "UNLOCK TABLES;", "DELIMITER ;;", "CREATE DEFINER=CURRENT_USER PROCEDURE", "SELECT 2; END;;", "DELIMITER ;"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("dump lost %q: %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "USE original_db") {
		t.Fatal("source database selection was not removed")
	}
}

func TestDatabaseRestoreDefinersStreamLongHexDataWithoutRewriting(t *testing.T) {
	sql := "INSERT INTO data VALUES (0x" + strings.Repeat("abcdef0123456789", 32768) + ");\n"
	var out bytes.Buffer
	if err := rebindDatabaseRestoreDefiners(&out, strings.NewReader(sql)); err != nil {
		t.Fatal(err)
	}
	if out.String() != sql {
		t.Fatal("long hex literal was truncated or reinterpreted")
	}
}
