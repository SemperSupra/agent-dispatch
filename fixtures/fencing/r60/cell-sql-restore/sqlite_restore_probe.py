"""Disposable SQLite backup-rollback and independent-receipt simulation. Not production authority."""
import sqlite3,tempfile,shutil,pathlib,json

def main():
    with tempfile.TemporaryDirectory(prefix='ad-r60-sql-') as td:
        root=pathlib.Path(td);db=root/'active.db';old=root/'old.db'
        c=sqlite3.connect(db)
        c.execute('PRAGMA synchronous=FULL')
        c.executescript('CREATE TABLE authority(epoch INTEGER NOT NULL, budget INTEGER NOT NULL, reserved INTEGER NOT NULL);CREATE TABLE effects(id TEXT PRIMARY KEY,state TEXT NOT NULL);INSERT INTO authority VALUES (11,1,0);')
        c.commit()
        with sqlite3.connect(old) as snap: c.backup(snap)
        c.execute("INSERT INTO effects VALUES ('unknown-before-crash','UNKNOWN')")
        c.execute('UPDATE authority SET reserved=reserved+1')
        c.commit(); assert c.execute('SELECT reserved FROM authority').fetchone()[0]==1
        c.close()
        # Model a user-authorized but stale restore: DB-local transactions do not stop it.
        shutil.copyfile(old,db)
        c=sqlite3.connect(db)
        assert c.execute('SELECT reserved FROM authority').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM effects').fetchone()[0]==0
        c.execute("INSERT INTO effects VALUES ('new-admission','UNKNOWN')")
        c.execute('UPDATE authority SET reserved=reserved+1')
        c.commit()
        assert c.execute('SELECT reserved FROM authority').fetchone()[0]==1
        # An independent authenticated, monotonic receipt/high-water would expose the loss;
        # this comparison remains synthetic, not an implementation.
        independently_known_unknown={'unknown-before-crash'}
        local_unknown={row[0] for row in c.execute("SELECT id FROM effects WHERE state='UNKNOWN'")}
        assert not independently_known_unknown.issubset(local_unknown)
        c.close()
        print(json.dumps({'venue':'disposable_local_sqlite','old_snapshot_restores_cleanly':'EXPECTED_RED','unknown_liability_eradicated_by_rollback':'EXPECTED_RED','new_budget_admission_after_restore':'EXPECTED_RED','external_receipt_comparison':'LOSS_DETECTED_SYNTHETIC','cloudflare_pitr':'NOT_TESTED','at_sink_fencing':'NOT_TESTED','pass':True},sort_keys=True))
if __name__=='__main__':main()
