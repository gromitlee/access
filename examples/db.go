package examples

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DBType uint8

const (
	dbName = "access_test"

	dbMysql      DBType = 1
	dbPostgresql DBType = 2
)

func getDB(dbTyp DBType, dbName string) *gorm.DB {
	dbLog := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Millisecond * 100,
			Colorful:                  true,
			IgnoreRecordNotFoundError: true,
			LogLevel:                  logger.Info,
		},
	)
	var db *gorm.DB
	var err error
	switch dbTyp {
	case dbMysql:
		db, err = gorm.Open(mysql.Open(fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8&parseTime=%t&loc=%s",
			"root",
			"gromit1234",
			"localhost:3306",
			dbName,
			true,
			// "Asia/Shanghai",
			"Local")), &gorm.Config{
			Logger: dbLog,
		})
		if err != nil {
			break
		}
		db.Set("gorm:table_options", "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")
		err = setPoolParam(db, 64, 64)
	case dbPostgresql:
		db, err = gorm.Open(postgres.Open(fmt.Sprintf("postgres://%s:%s@%s/%s",
			"postgres",
			"gromit1234",
			"localhost:5432",
			dbName,
		)), &gorm.Config{
			Logger: dbLog,
		})
		if err != nil {
			break
		}
		err = setPoolParam(db, 64, 64)
	default:
		log.Fatal(fmt.Errorf("unknown db type %v", dbTyp))
	}
	if err != nil {
		log.Fatal(err)
	}
	return db
}

// setPool 设置连接池参数
func setPoolParam(db *gorm.DB, maxOpenConn, maxIdleConn int) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(maxOpenConn)
	sqlDB.SetMaxIdleConns(maxIdleConn)
	return nil
}
