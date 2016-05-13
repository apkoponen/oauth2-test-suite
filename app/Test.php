<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Test extends Model
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = ['name'];

    /**
     * Return a test with the given name. Created to DB, if does not exist.
     *
     * @param string $name        Name for the test (unique).
     * @param string $description Description of the test
     *
     * @return Test Test with the given nam
     */
    public static function describe($name, $description)
    {
        $test = Test::firstOrNew(['name' => $name]);
        if($test->description != $description) {
            $test->description = $description;
            $test->save();
        }
        return $test;
    }

    /**
     * Run a test case.
     *
     * @param string $description Description to save to DB.
     * @param callable $callback  Callback to evaluate, should return true.
     * @return TestCase
     */
    public function should($description, $callback)
    {
        $testCase = TestCase::firstOrNew([
            'description' => $description,
            'test_id' => $this->id
        ]);
        $result = call_user_func($callback);
        $testCase->status = ($result) ? 'pass' : 'fail';
        $testCase->save();
        
        return $result;
    }

    /**
     * Define a relationship to TestCase.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function cases()
    {
        return $this->hasMany('App\TestCase');
    }

    /**
     * Prepare a tests collection for view.
     *
     * @param collection $tests A collection of tests
     * @return $tests A collection of tests
     */
    public static function prepareTestsForView($tests) {
      return $tests->map(function($test) {

            // Check if all cases have passed
            $casesPass = $test->cases->first(function($key, $case) {
                return $case->status === 'fail';
            });
            $test->status = (empty($casesPass)) ? 'pass' : 'fail';

            // Sort cases based on their status (failed first)
            $test->cases = $test->cases->sort(function($a, $b) {
                if($a === $b) {
                    return 0;
                }
                return ($a->status === 'fail') ? -1 : 1;
            });

            return $test;
        });
    }
}
