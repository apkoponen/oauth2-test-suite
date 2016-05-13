<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class TestCase extends Model
{
    /**
    * The attributes that are mass assignable.
    *
    * @var array
    */
    protected $fillable = ['description', 'test_id'];

    /**
    * Relationship to Test.
    *
    * @return [type] [description]
    */
    public function test()
    {
      return $this->belongsTo('App\Test');
    }
}
