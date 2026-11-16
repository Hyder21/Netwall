package com.example.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        SecurityEventEntity::class,
        PortRuleEntity::class,
        AppFirewallRuleEntity::class,
        BlockedDomainEntity::class,
        ScanReportEntity::class,
        TrustedNetworkEntity::class
    ],
    version = 2,
    exportSchema = false
)
abstract class NetShieldDatabase : RoomDatabase() {
    abstract fun netShieldDao(): NetShieldDao

    companion object {
        @Volatile
        private var INSTANCE: NetShieldDatabase? = null

        fun getInstance(context: Context): NetShieldDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    NetShieldDatabase::class.java,
                    "netshield_security.db"
                )
                    .fallbackToDestructiveMigration(dropAllTables = true)
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
